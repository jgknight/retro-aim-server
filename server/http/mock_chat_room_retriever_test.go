// Code generated by mockery v2.53.3. DO NOT EDIT.

package http

import (
	context "context"

	state "github.com/mk6i/retro-aim-server/state"
	mock "github.com/stretchr/testify/mock"
)

// mockChatRoomRetriever is an autogenerated mock type for the ChatRoomRetriever type
type mockChatRoomRetriever struct {
	mock.Mock
}

type mockChatRoomRetriever_Expecter struct {
	mock *mock.Mock
}

func (_m *mockChatRoomRetriever) EXPECT() *mockChatRoomRetriever_Expecter {
	return &mockChatRoomRetriever_Expecter{mock: &_m.Mock}
}

// AllChatRooms provides a mock function with given fields: ctx, exchange
func (_m *mockChatRoomRetriever) AllChatRooms(ctx context.Context, exchange uint16) ([]state.ChatRoom, error) {
	ret := _m.Called(ctx, exchange)

	if len(ret) == 0 {
		panic("no return value specified for AllChatRooms")
	}

	var r0 []state.ChatRoom
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uint16) ([]state.ChatRoom, error)); ok {
		return rf(ctx, exchange)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uint16) []state.ChatRoom); ok {
		r0 = rf(ctx, exchange)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]state.ChatRoom)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, uint16) error); ok {
		r1 = rf(ctx, exchange)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockChatRoomRetriever_AllChatRooms_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AllChatRooms'
type mockChatRoomRetriever_AllChatRooms_Call struct {
	*mock.Call
}

// AllChatRooms is a helper method to define mock.On call
//   - ctx context.Context
//   - exchange uint16
func (_e *mockChatRoomRetriever_Expecter) AllChatRooms(ctx interface{}, exchange interface{}) *mockChatRoomRetriever_AllChatRooms_Call {
	return &mockChatRoomRetriever_AllChatRooms_Call{Call: _e.mock.On("AllChatRooms", ctx, exchange)}
}

func (_c *mockChatRoomRetriever_AllChatRooms_Call) Run(run func(ctx context.Context, exchange uint16)) *mockChatRoomRetriever_AllChatRooms_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(uint16))
	})
	return _c
}

func (_c *mockChatRoomRetriever_AllChatRooms_Call) Return(_a0 []state.ChatRoom, _a1 error) *mockChatRoomRetriever_AllChatRooms_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockChatRoomRetriever_AllChatRooms_Call) RunAndReturn(run func(context.Context, uint16) ([]state.ChatRoom, error)) *mockChatRoomRetriever_AllChatRooms_Call {
	_c.Call.Return(run)
	return _c
}

// newMockChatRoomRetriever creates a new instance of mockChatRoomRetriever. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newMockChatRoomRetriever(t interface {
	mock.TestingT
	Cleanup(func())
}) *mockChatRoomRetriever {
	mock := &mockChatRoomRetriever{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
