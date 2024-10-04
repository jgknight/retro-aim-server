package foodgroup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mk6i/retro-aim-server/config"
	"github.com/mk6i/retro-aim-server/state"
	"github.com/mk6i/retro-aim-server/wire"

	"github.com/google/uuid"
)

// NewAuthService creates a new instance of AuthService.
func NewAuthService(
	cfg config.Config,
	sessionManager SessionManager,
	chatSessionRegistry ChatSessionRegistry,
	userManager UserManager,
	legacyBuddyListManager LegacyBuddyListManager,
	cookieBaker CookieBaker,
	messageRelayer MessageRelayer,
	feedbagManager FeedbagManager,
	chatMessageRelayer ChatMessageRelayer,
	accountManager AccountManager,
) *AuthService {
	return &AuthService{
		buddyUpdateBroadcaster: NewBuddyService(messageRelayer, feedbagManager, legacyBuddyListManager),
		chatSessionRegistry:    chatSessionRegistry,
		config:                 cfg,
		cookieBaker:            cookieBaker,
		legacyBuddyListManager: legacyBuddyListManager,
		sessionManager:         sessionManager,
		userManager:            userManager,
		chatMessageRelayer:     chatMessageRelayer,
		accountManager:         accountManager,
	}
}

// AuthService provides client login and session management services. It
// supports both FLAP (AIM v1.0-v3.0) and BUCP (AIM v3.5-v5.9) authentication
// modes.
type AuthService struct {
	buddyUpdateBroadcaster buddyBroadcaster
	chatMessageRelayer     ChatMessageRelayer
	chatSessionRegistry    ChatSessionRegistry
	config                 config.Config
	cookieBaker            CookieBaker
	legacyBuddyListManager LegacyBuddyListManager
	sessionManager         SessionManager
	userManager            UserManager
	chatRoomManager        ChatRoomRegistry
	accountManager         AccountManager
}

// RegisterChatSession adds a user to a chat room. The authCookie param is an
// opaque token returned by {{OServiceService.ServiceRequest}} that identifies
// the user and chat room. It returns the session object registered in the
// ChatSessionRegistry.
// This method does not verify that the user and chat room exist because it
// implicitly trusts the contents of the token signed by
// {{OServiceService.ServiceRequest}}.
func (s AuthService) RegisterChatSession(authCookie []byte) (*state.Session, error) {
	token, err := s.cookieBaker.Crack(authCookie)
	if err != nil {
		return nil, err
	}
	c := chatLoginCookie{}
	if err := wire.UnmarshalBE(&c, bytes.NewBuffer(token)); err != nil {
		return nil, err
	}
	return s.chatSessionRegistry.AddSession(c.ChatCookie, c.ScreenName), nil
}

type bosCookie struct {
	ScreenName state.DisplayScreenName `oscar:"len_prefix=uint8"`
	TLVList    wire.TLVList
}

// RegisterBOSSession adds a new session to the session registry.
func (s AuthService) RegisterBOSSession(authCookie []byte) (*state.Session, error) {
	buf, err := s.cookieBaker.Crack(authCookie)
	if err != nil {
		return nil, err
	}

	c := bosCookie{}
	if err := wire.UnmarshalBE(&c, bytes.NewBuffer(buf)); err != nil {
		return nil, err
	}

	u, err := s.userManager.User(c.ScreenName.IdentScreenName())
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user: %w", err)
	}
	if u == nil {
		return nil, fmt.Errorf("user not found")
	}

	sess := s.sessionManager.AddSession(u.DisplayScreenName)

	setSessionClientSoftware(sess, c)
	err = setSessionUserInfoFlags(sess, u, s.accountManager)
	if err != nil {
		return nil, err
	}

	if u.DisplayScreenName.IsUIN() {
		uin, err := strconv.Atoi(u.IdentScreenName.String())
		if err != nil {
			return nil, fmt.Errorf("error converting username to UIN: %w", err)
		}
		sess.SetUIN(uint32(uin))
	}

	return sess, nil
}

// RetrieveBOSSession returns a user's existing session
func (s AuthService) RetrieveBOSSession(authCookie []byte) (*state.Session, error) {
	buf, err := s.cookieBaker.Crack(authCookie)
	if err != nil {
		return nil, err
	}

	c := bosCookie{}
	if err := wire.UnmarshalBE(&c, bytes.NewBuffer(buf)); err != nil {
		return nil, err
	}

	u, err := s.userManager.User(c.ScreenName.IdentScreenName())
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user: %w", err)
	}
	if u == nil {
		return nil, fmt.Errorf("user not found")
	}

	return s.sessionManager.RetrieveSession(u.IdentScreenName), nil
}

// Signout removes this user's session and notifies users who have this user on
// their buddy list about this user's departure.
func (s AuthService) Signout(ctx context.Context, sess *state.Session) error {
	if err := s.buddyUpdateBroadcaster.BroadcastBuddyDeparted(ctx, sess); err != nil {
		return err
	}
	s.sessionManager.RemoveSession(sess)
	s.legacyBuddyListManager.DeleteUser(sess.IdentScreenName())
	return nil
}

// SignoutChat removes user from chat room and notifies remaining participants
// of their departure.
func (s AuthService) SignoutChat(ctx context.Context, sess *state.Session) {
	alertUserLeft(ctx, sess, s.chatMessageRelayer)
	s.chatSessionRegistry.RemoveSession(sess)
}

// BUCPChallenge processes a BUCP authentication challenge request. It
// retrieves the user's auth key based on the screen name provided in the
// request. The client uses the auth key to salt the MD5 password hash provided
// in the subsequent login request. If the account is valid, return
// SNAC(0x17,0x07), otherwise return SNAC(0x17,0x03).
func (s AuthService) BUCPChallenge(
	bodyIn wire.SNAC_0x17_0x06_BUCPChallengeRequest,
	newUUIDFn func() uuid.UUID,
) (wire.SNACMessage, error) {

	screenName, exists := bodyIn.String(wire.LoginTLVTagsScreenName)
	if !exists {
		return wire.SNACMessage{}, errors.New("screen name doesn't exist in tlv")
	}

	var authKey string

	user, err := s.userManager.User(state.NewIdentScreenName(screenName))
	if err != nil {
		return wire.SNACMessage{}, err
	}

	switch {
	case user != nil:
		// user lookup succeeded
		authKey = user.AuthKey
	case s.config.DisableAuth:
		// can't find user, generate stub auth key
		authKey = newUUIDFn().String()
	default:
		// can't find user, return login error
		return wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.BUCP,
				SubGroup:  wire.BUCPLoginResponse,
			},
			Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: []wire.TLV{
						wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrInvalidUsernameOrPassword),
					},
				},
			},
		}, nil
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.BUCP,
			SubGroup:  wire.BUCPChallengeResponse,
		},
		Body: wire.SNAC_0x17_0x07_BUCPChallengeResponse{
			AuthKey: authKey,
		},
	}, nil
}

// BUCPLogin processes a BUCP authentication request for AIM v3.5-v5.9. Upon
// successful login, a session is created.
// If login credentials are invalid and app config DisableAuth is true, a stub
// user is created and login continues as normal. DisableAuth allows you to
// skip the account creation procedure, which simplifies the login flow during
// development.
// If login is successful, the SNAC TLV list contains the BOS server address
// (wire.LoginTLVTagsReconnectHere) and an authorization cookie
// (wire.LoginTLVTagsAuthorizationCookie). Else, an error code is set
// (wire.LoginTLVTagsErrorSubcode).
func (s AuthService) BUCPLogin(bodyIn wire.SNAC_0x17_0x02_BUCPLoginRequest, newUserFn func(screenName state.DisplayScreenName) (state.User, error)) (wire.SNACMessage, error) {

	block, err := s.login(bodyIn.TLVList, newUserFn)
	if err != nil {
		return wire.SNACMessage{}, err
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.BUCP,
			SubGroup:  wire.BUCPLoginResponse,
		},
		Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{
			TLVRestBlock: block,
		},
	}, nil
}

// FLAPLogin processes a FLAP authentication request for AIM v1.0-v3.0. Upon
// successful login, a session is created.
// If login credentials are invalid and app config DisableAuth is true, a stub
// user is created and login continues as normal. DisableAuth allows you to
// skip the account creation procedure, which simplifies the login flow during
// development.
// If login is successful, the SNAC TLV list contains the BOS server address
// (wire.LoginTLVTagsReconnectHere) and an authorization cookie
// (wire.LoginTLVTagsAuthorizationCookie). Else, an error code is set
// (wire.LoginTLVTagsErrorSubcode).
func (s AuthService) FLAPLogin(frame wire.FLAPSignonFrame, newUserFn func(screenName state.DisplayScreenName) (state.User, error)) (wire.TLVRestBlock, error) {
	return s.login(frame.TLVList, newUserFn)
}

// login validates a user's credentials and creates their session. it returns
// metadata used in both BUCP and FLAP authentication responses.
func (s AuthService) login(
	TLVList wire.TLVList,
	newUserFn func(screenName state.DisplayScreenName) (state.User, error),
) (wire.TLVRestBlock, error) {

	screenName, found := TLVList.String(wire.LoginTLVTagsScreenName)
	if !found {
		return wire.TLVRestBlock{}, errors.New("screen name doesn't exist in tlv")
	}

	sn := state.DisplayScreenName(screenName)

	user, err := s.userManager.User(sn.IdentScreenName())
	if err != nil {
		return wire.TLVRestBlock{}, err
	}

	if user == nil {
		if s.config.DisableAuth {
			handleValid := false
			if sn.IsUIN() {
				handleValid = sn.ValidateUIN() == nil
			} else {
				handleValid = sn.ValidateAIMHandle() == nil
			}
			if !handleValid {
				return loginFailureResponse(sn, wire.LoginErrInvalidUsernameOrPassword), nil
			}

			newUser, err := newUserFn(sn)
			if err != nil {
				return wire.TLVRestBlock{}, err
			}
			if err := s.userManager.InsertUser(newUser); err != nil {
				return wire.TLVRestBlock{}, err
			}

			return s.loginSuccessResponse(sn, TLVList, err)
		}

		loginErr := wire.LoginErrInvalidUsernameOrPassword
		if sn.IsUIN() {
			loginErr = wire.LoginErrICQUserErr
		}
		return loginFailureResponse(sn, loginErr), nil
	}

	if s.config.DisableAuth {
		return s.loginSuccessResponse(sn, TLVList, err)
	}

	var loginOK bool
	// get the password from the appropriate TLV. older clients have a
	// roasted password, newer clients have a hashed password. ICQ may omit
	// the password TLV when logging in without saved password.
	if md5Hash, hasMD5 := TLVList.Bytes(wire.LoginTLVTagsPasswordHash); hasMD5 {
		loginOK = user.ValidateHash(md5Hash)
	} else if roastedPass, hasRoasted := TLVList.Bytes(wire.LoginTLVTagsRoastedPassword); hasRoasted {
		loginOK = user.ValidateRoastedPass(roastedPass)
	}
	if !loginOK {
		return loginFailureResponse(sn, wire.LoginErrInvalidPassword), nil
	}

	return s.loginSuccessResponse(sn, TLVList, err)
}

func (s AuthService) loginSuccessResponse(screenName state.DisplayScreenName, tlvList wire.TLVList, err error) (wire.TLVRestBlock, error) {
	loginCookie := bosCookie{
		ScreenName: screenName,
		TLVList:    tlvList,
	}

	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(loginCookie, buf); err != nil {
		return wire.TLVRestBlock{}, err
	}
	cookie, err := s.cookieBaker.Issue(buf.Bytes())
	if err != nil {
		return wire.TLVRestBlock{}, fmt.Errorf("failed to issue auth cookie: %w", err)
	}

	return wire.TLVRestBlock{
		TLVList: []wire.TLV{
			wire.NewTLVBE(wire.LoginTLVTagsScreenName, screenName),
			wire.NewTLVBE(wire.LoginTLVTagsReconnectHere, net.JoinHostPort(s.config.OSCARHost, s.config.BOSPort)),
			wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, cookie),
		},
	}, nil
}

func loginFailureResponse(screenName state.DisplayScreenName, code uint16) wire.TLVRestBlock {
	return wire.TLVRestBlock{
		TLVList: []wire.TLV{
			wire.NewTLVBE(wire.LoginTLVTagsScreenName, screenName),
			wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, code),
		},
	}
}

// setSessionClientSoftware takes any potential Client Version TLVs out of the cookie and
// sets the values on the session.ClientSoftware struct
func setSessionClientSoftware(sess *state.Session, c bosCookie) {
	cs := state.ClientSoftware{}
	if clientIDString, hasClientIDString := c.TLVList.String(wire.LoginTLVTagsClientIDString); hasClientIDString {
		cs.ClientIDString = clientIDString
	}
	if clientCountry, hasClientCountry := c.TLVList.String(wire.LoginTLVTagsClientCountry); hasClientCountry {
		cs.ClientCountry = clientCountry
	}
	if clientLanguage, hasClientLanguage := c.TLVList.String(wire.LoginTLVTagsClientLanguage); hasClientLanguage {
		cs.ClientLanguage = clientLanguage
	}
	if clientDistNumb, hasClientDistNumb := c.TLVList.Uint32BE(wire.LoginTLVTagsClientDistributionNumber); hasClientDistNumb {
		cs.ClientDistributionNumber = clientDistNumb
	}
	if clientIDNumber, hasClientIDNumber := c.TLVList.Uint16BE(wire.LoginTLVTagsClientIDNumber); hasClientIDNumber {
		cs.ClientIDNumber = clientIDNumber
	}
	if clientMajorVer, hasClientMajorVer := c.TLVList.Uint16BE(wire.LoginTLVTagsClientMajorVersion); hasClientMajorVer {
		cs.ClientMajorVersion = clientMajorVer
	}
	if clientMinorVer, hasClientMinorVer := c.TLVList.Uint16BE(wire.LoginTLVTagsClientMinorVersion); hasClientMinorVer {
		cs.ClientMinorVersion = clientMinorVer
	}
	if clientLesserVer, hasClientLesserVer := c.TLVList.Uint16BE(wire.LoginTLVTagsClientLesserVersion); hasClientLesserVer {
		cs.ClientLesserVersion = clientLesserVer
	}
	if clientBuildNumber, hasClientBuildNumber := c.TLVList.Uint16BE(wire.LoginTLVTagsClientBuildNumber); hasClientBuildNumber {
		cs.ClientBuildNumber = clientBuildNumber
	}
	// if clientMultiConn, hasClientMultiConn := TLVList.Bytes(wire.LoginTLVTagsClientMultiConn); hasClientMultiConn {
	// 	c.ClientMultiConn = clientMultiConn
	// }
	sess.SetClientSoftware(cs)
}

// setSessionUserInfoFlags looks at attributes about the session, user, or client and
// sets the appropriate User Info flags on session.UserInfoFlags
func setSessionUserInfoFlags(sess *state.Session, u *state.User, am AccountManager) error {
	// Set the unconfirmed user info flag if this account is unconfirmed
	if confirmed, err := am.ConfirmStatusByName(sess.IdentScreenName()); err != nil {
		return fmt.Errorf("error setting unconfirmed user flag: %w", err)
	} else if !confirmed {
		sess.SetUserInfoFlag(wire.OServiceUserFlagUnconfirmed)
	}

	// Set the wireless user info flag if the user is on a known wireless device
	// todo: determine a better way than hardcoding known devices
	mobileClientIDStrings := []string{
		"MX240a", // MX240a Instant Messenger (MX240a)
		"WIN32",  // temp for testing
	}
	mobileClientIDNumbers := []uint16{
		0x00,
	}
	for _, client := range mobileClientIDStrings {
		if strings.Contains(sess.ClientSoftware().ClientIDString, client) {
			sess.SetUserInfoFlag(wire.OServiceUserFlagWireless)
			break
		}
	}
	for _, client := range mobileClientIDNumbers {
		if sess.ClientSoftware().ClientIDNumber == client {
			sess.SetUserInfoFlag(wire.OServiceUserFlagWireless)
			break
		}
	}

	// Set the ICQ user info flag if the user is an ICQ user
	if u.DisplayScreenName.IsUIN() {
		sess.SetUserInfoFlag(wire.OServiceUserFlagICQ)
	}
	return nil
}
