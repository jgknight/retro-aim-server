package oscar

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/retro-aim-server/state"
	"github.com/mk6i/retro-aim-server/wire"
)

// pipeRWC provides a mock for ReadWriteCloser that uses pipes instead of TCP
// connections
type pipeRWC struct {
	*io.PipeReader
	*io.PipeWriter
}

func (m pipeRWC) Close() error {
	if err := m.PipeReader.Close(); err != nil {
		return err
	}
	return m.PipeWriter.Close()
}

func TestBOSService_handleNewConnection(t *testing.T) {
	sess := state.NewSession()

	clientReader, serverWriter := io.Pipe()
	serverReader, clientWriter := io.Pipe()

	go func() {
		// < receive FLAPSignonFrame
		flap := wire.FLAPFrame{}
		assert.NoError(t, wire.Unmarshal(&flap, serverReader))
		buf, err := flap.ReadBody(serverReader)
		assert.NoError(t, err)
		flapSignonFrame := wire.FLAPSignonFrame{}
		assert.NoError(t, wire.Unmarshal(&flapSignonFrame, buf))

		// > send FLAPSignonFrame
		flapSignonFrame = wire.FLAPSignonFrame{
			FLAPVersion: 1,
		}
		flapSignonFrame.Append(wire.NewTLV(wire.OServiceTLVTagsLoginCookie, []byte("the-cookie")))
		buf = &bytes.Buffer{}
		assert.NoError(t, wire.Marshal(flapSignonFrame, buf))
		flap = wire.FLAPFrame{
			StartMarker:   42,
			FrameType:     wire.FLAPFrameSignon,
			PayloadLength: uint16(buf.Len()),
		}
		assert.NoError(t, wire.Marshal(flap, serverWriter))
		_, err = serverWriter.Write(buf.Bytes())
		assert.NoError(t, err)

		// < receive SNAC_0x01_0x03_OServiceHostOnline
		flap = wire.FLAPFrame{}
		assert.NoError(t, wire.Unmarshal(&flap, serverReader))
		buf, err = flap.ReadBody(serverReader)
		assert.NoError(t, err)
		frame := wire.SNACFrame{}
		assert.NoError(t, wire.Unmarshal(&frame, buf))
		body := wire.SNAC_0x01_0x03_OServiceHostOnline{}
		assert.NoError(t, wire.Unmarshal(&body, buf))

		// send the first request that should get relayed to BOSRouter.Handle
		flapc := wire.NewFlapClient(0, nil, serverWriter)
		frame = wire.SNACFrame{
			FoodGroup: wire.OService,
			SubGroup:  wire.OServiceClientOnline,
		}
		assert.NoError(t, flapc.SendSNAC(frame, struct{}{}))
		assert.NoError(t, serverWriter.Close())
	}()

	authService := newMockAuthService(t)
	authService.EXPECT().
		RegisterBOSSession([]byte("the-cookie")).
		Return(sess, nil)
	authService.EXPECT().
		Signout(mock.Anything, sess).
		Return(nil)

	onlineNotifier := newMockOnlineNotifier(t)
	onlineNotifier.EXPECT().
		HostOnline().
		Return(wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceHostOnline,
			},
			Body: wire.SNAC_0x01_0x03_OServiceHostOnline{},
		})

	router := newMockHandler(t)
	router.EXPECT().
		Handle(mock.Anything, sess, mock.Anything, mock.Anything, mock.Anything).
		Run(func(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter) {
			assert.Equal(t, wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceClientOnline,
			}, inFrame)
		}).Return(nil)

	rt := BOSServer{
		AuthService:    authService,
		Handler:        router,
		Logger:         slog.Default(),
		OnlineNotifier: onlineNotifier,
	}
	rwc := pipeRWC{
		PipeReader: clientReader,
		PipeWriter: clientWriter,
	}
	assert.NoError(t, rt.handleNewConnection(context.Background(), rwc))
}
