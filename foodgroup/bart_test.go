package foodgroup

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/retro-aim-server/state"
	"github.com/mk6i/retro-aim-server/wire"
)

func TestBARTService_UpsertItem(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// userSession is the session of the user adding to feedbag
		userSession *state.Session
		// inputSNAC is the SNAC sent from the client to the server
		inputSNAC wire.SNACMessage
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// expectOutput is the SNAC sent from the server to client
		expectOutput wire.SNACMessage
	}{
		{
			name:        "upsert item",
			userSession: newTestSession("user_screen_name"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x10_0x02_BARTUploadQuery{
					Type: 1,
					Data: []byte{'i', 't', 'e', 'm', 'd', 'a', 't', 'a'},
				},
			},
			mockParams: mockParams{
				buddyIconManagerParams: buddyIconManagerParams{
					buddyIconManagerUpsertParams: buddyIconManagerUpsertParams{
						{
							itemHash: []byte{0x4e, 0xd9, 0xc1, 0x96, 0x45, 0xdb, 0x5a, 0xec, 0xdb, 0xf5, 0xc7, 0xa2, 0x4e, 0x8e, 0xa0, 0xed},
							payload:  []byte{'i', 't', 'e', 'm', 'd', 'a', 't', 'a'},
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastBuddyArrivedParams: broadcastBuddyArrivedParams{
						{
							screenName: state.NewIdentScreenName("user_screen_name"),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BART,
					SubGroup:  wire.BARTUploadReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x10_0x03_BARTUploadReply{
					Code: wire.BARTReplyCodesSuccess,
					ID: wire.BARTID{
						Type: wire.BARTTypesBuddyIcon,
						BARTInfo: wire.BARTInfo{
							Flags: wire.BARTFlagsKnown,
							Hash:  []byte{0x4e, 0xd9, 0xc1, 0x96, 0x45, 0xdb, 0x5a, 0xec, 0xdb, 0xf5, 0xc7, 0xa2, 0x4e, 0x8e, 0xa0, 0xed},
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buddyIconManager := newMockBuddyIconManager(t)
			for _, params := range tc.mockParams.buddyIconManagerUpsertParams {
				buddyIconManager.EXPECT().
					SetBuddyIcon(matchContext(), params.itemHash, params.payload).
					Return(nil)
			}
			buddyUpdateBroadcaster := newMockbuddyBroadcaster(t)
			for _, params := range tc.mockParams.broadcastBuddyArrivedParams {
				buddyUpdateBroadcaster.EXPECT().
					BroadcastBuddyArrived(mock.Anything, matchSession(params.screenName)).
					Return(params.err)
			}
			svc := NewBARTService(slog.Default(), buddyIconManager, nil, nil, nil)
			svc.buddyUpdateBroadcaster = buddyUpdateBroadcaster

			output, err := svc.UpsertItem(context.Background(), tc.userSession, tc.inputSNAC.Frame,
				tc.inputSNAC.Body.(wire.SNAC_0x10_0x02_BARTUploadQuery))

			assert.NoError(t, err)
			assert.Equal(t, output, tc.expectOutput)
		})
	}
}

func TestBARTService_RetrieveItem(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// userSession is the session of the user adding to feedbag
		userSession *state.Session
		// inputSNAC is the SNAC sent from the client to the server
		inputSNAC wire.SNACMessage
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// expectOutput is the SNAC sent from the server to client
		expectOutput wire.SNACMessage
		// expectErr is the expected error
		expectErr error
	}{
		{
			name:        "retrieve buddy icon",
			userSession: newTestSession("user_screen_name"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x10_0x04_BARTDownloadQuery{
					ScreenName: "user_screen_name",
					Command:    1,
					BARTID: wire.BARTID{
						Type: wire.BARTTypesBuddyIcon,
						BARTInfo: wire.BARTInfo{
							Flags: wire.BARTFlagsKnown,
							Hash:  []byte{0x4e, 0xd9, 0xc1, 0x96, 0x45, 0xdb, 0x5a, 0xec, 0xdb, 0xf5, 0xc7, 0xa2, 0x4e, 0x8e, 0xa0, 0xed},
						},
					},
				},
			},
			mockParams: mockParams{
				buddyIconManagerParams: buddyIconManagerParams{
					buddyIconManagerRetrieveParams: buddyIconManagerRetrieveParams{
						{
							itemHash: []byte{0x4e, 0xd9, 0xc1, 0x96, 0x45, 0xdb, 0x5a, 0xec, 0xdb, 0xf5, 0xc7, 0xa2, 0x4e, 0x8e, 0xa0, 0xed},
							result:   []byte{'i', 't', 'e', 'm', 'd', 'a', 't', 'a'},
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BART,
					SubGroup:  wire.BARTDownloadReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x10_0x05_BARTDownloadReply{
					ScreenName: "user_screen_name",
					BARTID: wire.BARTID{
						Type: wire.BARTTypesBuddyIcon,
						BARTInfo: wire.BARTInfo{
							Flags: wire.BARTFlagsKnown,
							Hash:  []byte{0x4e, 0xd9, 0xc1, 0x96, 0x45, 0xdb, 0x5a, 0xec, 0xdb, 0xf5, 0xc7, 0xa2, 0x4e, 0x8e, 0xa0, 0xed},
						},
					},
					Data: []byte{'i', 't', 'e', 'm', 'd', 'a', 't', 'a'},
				},
			},
		},
		{
			name:        "retrieve blank icon used for clearing buddy icon",
			userSession: newTestSession("user_screen_name"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x10_0x04_BARTDownloadQuery{
					ScreenName: "user_screen_name",
					Command:    1,
					BARTID: wire.BARTID{
						Type: wire.BARTTypesBuddyIcon,
						BARTInfo: wire.BARTInfo{
							Flags: wire.BARTFlagsKnown,
							Hash:  wire.GetClearIconHash(),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BART,
					SubGroup:  wire.BARTDownloadReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x10_0x05_BARTDownloadReply{
					ScreenName: "user_screen_name",
					BARTID: wire.BARTID{
						Type: wire.BARTTypesBuddyIcon,
						BARTInfo: wire.BARTInfo{
							Flags: wire.BARTFlagsKnown,
							Hash:  wire.GetClearIconHash(),
						},
					},
					Data: blankGIF,
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buddyIconManager := newMockBuddyIconManager(t)
			for _, params := range tc.mockParams.buddyIconManagerParams.buddyIconManagerRetrieveParams {
				buddyIconManager.EXPECT().
					BuddyIcon(matchContext(), params.itemHash).
					Return(params.result, nil)
			}

			svc := NewBARTService(slog.Default(), buddyIconManager, nil, nil, nil)

			output, err := svc.RetrieveItem(context.Background(), tc.userSession, tc.inputSNAC.Frame,
				tc.inputSNAC.Body.(wire.SNAC_0x10_0x04_BARTDownloadQuery))

			assert.ErrorIs(t, err, tc.expectErr)
			if tc.expectErr != nil {
				return
			}
			assert.Equal(t, output, tc.expectOutput)
		})
	}
}
