package server

import (
	"context"
	"errors"
	"io"
	"net"
	"os"

	"github.com/mkaminski/goaim/oscar"
	"github.com/mkaminski/goaim/state"
)

type BOSService struct {
	AlertRouter
	AuthHandler
	BuddyRouter
	ChatNavRouter
	Config
	FeedbagRouter
	ICBMRouter
	LocateRouter
	OServiceBOSRouter
	RouteLogger
}

func (rt BOSService) Start() {
	addr := Address("", rt.Config.BOSPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		rt.Logger.Error("unable to bind BOS server address", "err", err.Error())
		os.Exit(1)
	}
	defer listener.Close()

	rt.Logger.Info("starting BOS service", "addr", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			rt.Logger.Error(err.Error())
			continue
		}
		ctx := context.Background()
		ctx = context.WithValue(ctx, "ip", conn.RemoteAddr().String())
		rt.Logger.DebugContext(ctx, "accepted connection")
		go rt.handleNewConnection(ctx, conn)
	}
}

func (rt BOSService) handleNewConnection(ctx context.Context, rwc io.ReadWriteCloser) {
	sess, seq, err := rt.VerifyLogin(rwc)
	if err != nil {
		rt.Logger.ErrorContext(ctx, "user disconnected with error", "err", err.Error())
		return
	}

	defer sess.Close()
	defer rwc.Close()

	go func() {
		<-sess.Closed()
		if err := rt.Signout(ctx, sess); err != nil {
			rt.Logger.ErrorContext(ctx, "error notifying departure", "err", err.Error())
		}
	}()

	ctx = context.WithValue(ctx, "screenName", sess.ScreenName())

	msg := rt.WriteOServiceHostOnline()
	if err := sendSNAC(oscar.SnacFrame{}, msg.SnacFrame, msg.SnacOut, &seq, rwc); err != nil {
		rt.Logger.ErrorContext(ctx, "error WriteOServiceHostOnline")
		return
	}

	fnClientReqHandler := func(ctx context.Context, r io.Reader, w io.Writer, seq *uint32) error {
		return rt.route(ctx, sess, r, w, seq)
	}
	fnAlertHandler := func(ctx context.Context, msg oscar.XMessage, w io.Writer, seq *uint32) error {
		return sendSNAC(oscar.SnacFrame{}, msg.SnacFrame, msg.SnacOut, seq, w)
	}
	dispatchIncomingMessages(ctx, sess, seq, rwc, rt.Logger, fnClientReqHandler, fnAlertHandler)
}

func (rt BOSService) route(ctx context.Context, sess *state.Session, r io.Reader, w io.Writer, sequence *uint32) error {
	snac := oscar.SnacFrame{}
	if err := oscar.Unmarshal(&snac, r); err != nil {
		return err
	}

	err := func() error {
		switch snac.FoodGroup {
		case oscar.OSERVICE:
			return rt.RouteOService(ctx, sess, snac, r, w, sequence)
		case oscar.LOCATE:
			return rt.RouteLocate(ctx, sess, snac, r, w, sequence)
		case oscar.BUDDY:
			return rt.RouteBuddy(ctx, snac, r, w, sequence)
		case oscar.ICBM:
			return rt.RouteICBM(ctx, sess, snac, r, w, sequence)
		case oscar.CHAT_NAV:
			return rt.RouteChatNav(ctx, sess, snac, r, w, sequence)
		case oscar.FEEDBAG:
			return rt.RouteFeedbag(ctx, sess, snac, r, w, sequence)
		case oscar.BUCP:
			return routeBUCP(ctx)
		case oscar.ALERT:
			return rt.RouteAlert(ctx, snac)
		default:
			return ErrUnsupportedSubGroup
		}
	}()

	if err != nil {
		rt.logRequestError(ctx, snac, err)
		if errors.Is(err, ErrUnsupportedSubGroup) {
			if err1 := sendInvalidSNACErr(snac, w, sequence); err1 != nil {
				err = errors.Join(err1, err)
			}
			if rt.Config.FailFast {
				panic(err.Error())
			}
			return nil
		}
	}

	return err
}