// Code generated by mockery v2.40.1. DO NOT EDIT.

package handler

import (
	context "context"

	state "github.com/mk6i/retro-aim-server/state"
	mock "github.com/stretchr/testify/mock"

	wire "github.com/mk6i/retro-aim-server/wire"
)

// mockOServiceBOSService is an autogenerated mock type for the OServiceBOSService type
type mockOServiceBOSService struct {
	mock.Mock
}

type mockOServiceBOSService_Expecter struct {
	mock *mock.Mock
}

func (_m *mockOServiceBOSService) EXPECT() *mockOServiceBOSService_Expecter {
	return &mockOServiceBOSService_Expecter{mock: &_m.Mock}
}

// ClientOnline provides a mock function with given fields: ctx, bodyIn, sess
func (_m *mockOServiceBOSService) ClientOnline(ctx context.Context, bodyIn wire.SNAC_0x01_0x02_OServiceClientOnline, sess *state.Session) error {
	ret := _m.Called(ctx, bodyIn, sess)

	if len(ret) == 0 {
		panic("no return value specified for ClientOnline")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, wire.SNAC_0x01_0x02_OServiceClientOnline, *state.Session) error); ok {
		r0 = rf(ctx, bodyIn, sess)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// mockOServiceBOSService_ClientOnline_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ClientOnline'
type mockOServiceBOSService_ClientOnline_Call struct {
	*mock.Call
}

// ClientOnline is a helper method to define mock.On call
//   - ctx context.Context
//   - bodyIn wire.SNAC_0x01_0x02_OServiceClientOnline
//   - sess *state.Session
func (_e *mockOServiceBOSService_Expecter) ClientOnline(ctx interface{}, bodyIn interface{}, sess interface{}) *mockOServiceBOSService_ClientOnline_Call {
	return &mockOServiceBOSService_ClientOnline_Call{Call: _e.mock.On("ClientOnline", ctx, bodyIn, sess)}
}

func (_c *mockOServiceBOSService_ClientOnline_Call) Run(run func(ctx context.Context, bodyIn wire.SNAC_0x01_0x02_OServiceClientOnline, sess *state.Session)) *mockOServiceBOSService_ClientOnline_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(wire.SNAC_0x01_0x02_OServiceClientOnline), args[2].(*state.Session))
	})
	return _c
}

func (_c *mockOServiceBOSService_ClientOnline_Call) Return(_a0 error) *mockOServiceBOSService_ClientOnline_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockOServiceBOSService_ClientOnline_Call) RunAndReturn(run func(context.Context, wire.SNAC_0x01_0x02_OServiceClientOnline, *state.Session) error) *mockOServiceBOSService_ClientOnline_Call {
	_c.Call.Return(run)
	return _c
}

// ClientVersions provides a mock function with given fields: ctx, frame, bodyIn
func (_m *mockOServiceBOSService) ClientVersions(ctx context.Context, frame wire.SNACFrame, bodyIn wire.SNAC_0x01_0x17_OServiceClientVersions) wire.SNACMessage {
	ret := _m.Called(ctx, frame, bodyIn)

	if len(ret) == 0 {
		panic("no return value specified for ClientVersions")
	}

	var r0 wire.SNACMessage
	if rf, ok := ret.Get(0).(func(context.Context, wire.SNACFrame, wire.SNAC_0x01_0x17_OServiceClientVersions) wire.SNACMessage); ok {
		r0 = rf(ctx, frame, bodyIn)
	} else {
		r0 = ret.Get(0).(wire.SNACMessage)
	}

	return r0
}

// mockOServiceBOSService_ClientVersions_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ClientVersions'
type mockOServiceBOSService_ClientVersions_Call struct {
	*mock.Call
}

// ClientVersions is a helper method to define mock.On call
//   - ctx context.Context
//   - frame wire.SNACFrame
//   - bodyIn wire.SNAC_0x01_0x17_OServiceClientVersions
func (_e *mockOServiceBOSService_Expecter) ClientVersions(ctx interface{}, frame interface{}, bodyIn interface{}) *mockOServiceBOSService_ClientVersions_Call {
	return &mockOServiceBOSService_ClientVersions_Call{Call: _e.mock.On("ClientVersions", ctx, frame, bodyIn)}
}

func (_c *mockOServiceBOSService_ClientVersions_Call) Run(run func(ctx context.Context, frame wire.SNACFrame, bodyIn wire.SNAC_0x01_0x17_OServiceClientVersions)) *mockOServiceBOSService_ClientVersions_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(wire.SNACFrame), args[2].(wire.SNAC_0x01_0x17_OServiceClientVersions))
	})
	return _c
}

func (_c *mockOServiceBOSService_ClientVersions_Call) Return(_a0 wire.SNACMessage) *mockOServiceBOSService_ClientVersions_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockOServiceBOSService_ClientVersions_Call) RunAndReturn(run func(context.Context, wire.SNACFrame, wire.SNAC_0x01_0x17_OServiceClientVersions) wire.SNACMessage) *mockOServiceBOSService_ClientVersions_Call {
	_c.Call.Return(run)
	return _c
}

// HostOnline provides a mock function with given fields:
func (_m *mockOServiceBOSService) HostOnline() wire.SNACMessage {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for HostOnline")
	}

	var r0 wire.SNACMessage
	if rf, ok := ret.Get(0).(func() wire.SNACMessage); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(wire.SNACMessage)
	}

	return r0
}

// mockOServiceBOSService_HostOnline_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HostOnline'
type mockOServiceBOSService_HostOnline_Call struct {
	*mock.Call
}

// HostOnline is a helper method to define mock.On call
func (_e *mockOServiceBOSService_Expecter) HostOnline() *mockOServiceBOSService_HostOnline_Call {
	return &mockOServiceBOSService_HostOnline_Call{Call: _e.mock.On("HostOnline")}
}

func (_c *mockOServiceBOSService_HostOnline_Call) Run(run func()) *mockOServiceBOSService_HostOnline_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *mockOServiceBOSService_HostOnline_Call) Return(_a0 wire.SNACMessage) *mockOServiceBOSService_HostOnline_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockOServiceBOSService_HostOnline_Call) RunAndReturn(run func() wire.SNACMessage) *mockOServiceBOSService_HostOnline_Call {
	_c.Call.Return(run)
	return _c
}

// IdleNotification provides a mock function with given fields: ctx, sess, bodyIn
func (_m *mockOServiceBOSService) IdleNotification(ctx context.Context, sess *state.Session, bodyIn wire.SNAC_0x01_0x11_OServiceIdleNotification) error {
	ret := _m.Called(ctx, sess, bodyIn)

	if len(ret) == 0 {
		panic("no return value specified for IdleNotification")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *state.Session, wire.SNAC_0x01_0x11_OServiceIdleNotification) error); ok {
		r0 = rf(ctx, sess, bodyIn)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// mockOServiceBOSService_IdleNotification_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IdleNotification'
type mockOServiceBOSService_IdleNotification_Call struct {
	*mock.Call
}

// IdleNotification is a helper method to define mock.On call
//   - ctx context.Context
//   - sess *state.Session
//   - bodyIn wire.SNAC_0x01_0x11_OServiceIdleNotification
func (_e *mockOServiceBOSService_Expecter) IdleNotification(ctx interface{}, sess interface{}, bodyIn interface{}) *mockOServiceBOSService_IdleNotification_Call {
	return &mockOServiceBOSService_IdleNotification_Call{Call: _e.mock.On("IdleNotification", ctx, sess, bodyIn)}
}

func (_c *mockOServiceBOSService_IdleNotification_Call) Run(run func(ctx context.Context, sess *state.Session, bodyIn wire.SNAC_0x01_0x11_OServiceIdleNotification)) *mockOServiceBOSService_IdleNotification_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*state.Session), args[2].(wire.SNAC_0x01_0x11_OServiceIdleNotification))
	})
	return _c
}

func (_c *mockOServiceBOSService_IdleNotification_Call) Return(_a0 error) *mockOServiceBOSService_IdleNotification_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockOServiceBOSService_IdleNotification_Call) RunAndReturn(run func(context.Context, *state.Session, wire.SNAC_0x01_0x11_OServiceIdleNotification) error) *mockOServiceBOSService_IdleNotification_Call {
	_c.Call.Return(run)
	return _c
}

// RateParamsQuery provides a mock function with given fields: ctx, frame
func (_m *mockOServiceBOSService) RateParamsQuery(ctx context.Context, frame wire.SNACFrame) wire.SNACMessage {
	ret := _m.Called(ctx, frame)

	if len(ret) == 0 {
		panic("no return value specified for RateParamsQuery")
	}

	var r0 wire.SNACMessage
	if rf, ok := ret.Get(0).(func(context.Context, wire.SNACFrame) wire.SNACMessage); ok {
		r0 = rf(ctx, frame)
	} else {
		r0 = ret.Get(0).(wire.SNACMessage)
	}

	return r0
}

// mockOServiceBOSService_RateParamsQuery_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RateParamsQuery'
type mockOServiceBOSService_RateParamsQuery_Call struct {
	*mock.Call
}

// RateParamsQuery is a helper method to define mock.On call
//   - ctx context.Context
//   - frame wire.SNACFrame
func (_e *mockOServiceBOSService_Expecter) RateParamsQuery(ctx interface{}, frame interface{}) *mockOServiceBOSService_RateParamsQuery_Call {
	return &mockOServiceBOSService_RateParamsQuery_Call{Call: _e.mock.On("RateParamsQuery", ctx, frame)}
}

func (_c *mockOServiceBOSService_RateParamsQuery_Call) Run(run func(ctx context.Context, frame wire.SNACFrame)) *mockOServiceBOSService_RateParamsQuery_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(wire.SNACFrame))
	})
	return _c
}

func (_c *mockOServiceBOSService_RateParamsQuery_Call) Return(_a0 wire.SNACMessage) *mockOServiceBOSService_RateParamsQuery_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockOServiceBOSService_RateParamsQuery_Call) RunAndReturn(run func(context.Context, wire.SNACFrame) wire.SNACMessage) *mockOServiceBOSService_RateParamsQuery_Call {
	_c.Call.Return(run)
	return _c
}

// RateParamsSubAdd provides a mock function with given fields: _a0, _a1
func (_m *mockOServiceBOSService) RateParamsSubAdd(_a0 context.Context, _a1 wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd) {
	_m.Called(_a0, _a1)
}

// mockOServiceBOSService_RateParamsSubAdd_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RateParamsSubAdd'
type mockOServiceBOSService_RateParamsSubAdd_Call struct {
	*mock.Call
}

// RateParamsSubAdd is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd
func (_e *mockOServiceBOSService_Expecter) RateParamsSubAdd(_a0 interface{}, _a1 interface{}) *mockOServiceBOSService_RateParamsSubAdd_Call {
	return &mockOServiceBOSService_RateParamsSubAdd_Call{Call: _e.mock.On("RateParamsSubAdd", _a0, _a1)}
}

func (_c *mockOServiceBOSService_RateParamsSubAdd_Call) Run(run func(_a0 context.Context, _a1 wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd)) *mockOServiceBOSService_RateParamsSubAdd_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd))
	})
	return _c
}

func (_c *mockOServiceBOSService_RateParamsSubAdd_Call) Return() *mockOServiceBOSService_RateParamsSubAdd_Call {
	_c.Call.Return()
	return _c
}

func (_c *mockOServiceBOSService_RateParamsSubAdd_Call) RunAndReturn(run func(context.Context, wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd)) *mockOServiceBOSService_RateParamsSubAdd_Call {
	_c.Call.Return(run)
	return _c
}

// ServiceRequest provides a mock function with given fields: ctx, sess, frame, bodyIn
func (_m *mockOServiceBOSService) ServiceRequest(ctx context.Context, sess *state.Session, frame wire.SNACFrame, bodyIn wire.SNAC_0x01_0x04_OServiceServiceRequest) (wire.SNACMessage, error) {
	ret := _m.Called(ctx, sess, frame, bodyIn)

	if len(ret) == 0 {
		panic("no return value specified for ServiceRequest")
	}

	var r0 wire.SNACMessage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *state.Session, wire.SNACFrame, wire.SNAC_0x01_0x04_OServiceServiceRequest) (wire.SNACMessage, error)); ok {
		return rf(ctx, sess, frame, bodyIn)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *state.Session, wire.SNACFrame, wire.SNAC_0x01_0x04_OServiceServiceRequest) wire.SNACMessage); ok {
		r0 = rf(ctx, sess, frame, bodyIn)
	} else {
		r0 = ret.Get(0).(wire.SNACMessage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, *state.Session, wire.SNACFrame, wire.SNAC_0x01_0x04_OServiceServiceRequest) error); ok {
		r1 = rf(ctx, sess, frame, bodyIn)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockOServiceBOSService_ServiceRequest_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ServiceRequest'
type mockOServiceBOSService_ServiceRequest_Call struct {
	*mock.Call
}

// ServiceRequest is a helper method to define mock.On call
//   - ctx context.Context
//   - sess *state.Session
//   - frame wire.SNACFrame
//   - bodyIn wire.SNAC_0x01_0x04_OServiceServiceRequest
func (_e *mockOServiceBOSService_Expecter) ServiceRequest(ctx interface{}, sess interface{}, frame interface{}, bodyIn interface{}) *mockOServiceBOSService_ServiceRequest_Call {
	return &mockOServiceBOSService_ServiceRequest_Call{Call: _e.mock.On("ServiceRequest", ctx, sess, frame, bodyIn)}
}

func (_c *mockOServiceBOSService_ServiceRequest_Call) Run(run func(ctx context.Context, sess *state.Session, frame wire.SNACFrame, bodyIn wire.SNAC_0x01_0x04_OServiceServiceRequest)) *mockOServiceBOSService_ServiceRequest_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*state.Session), args[2].(wire.SNACFrame), args[3].(wire.SNAC_0x01_0x04_OServiceServiceRequest))
	})
	return _c
}

func (_c *mockOServiceBOSService_ServiceRequest_Call) Return(_a0 wire.SNACMessage, _a1 error) *mockOServiceBOSService_ServiceRequest_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockOServiceBOSService_ServiceRequest_Call) RunAndReturn(run func(context.Context, *state.Session, wire.SNACFrame, wire.SNAC_0x01_0x04_OServiceServiceRequest) (wire.SNACMessage, error)) *mockOServiceBOSService_ServiceRequest_Call {
	_c.Call.Return(run)
	return _c
}

// SetUserInfoFields provides a mock function with given fields: ctx, sess, frame, bodyIn
func (_m *mockOServiceBOSService) SetUserInfoFields(ctx context.Context, sess *state.Session, frame wire.SNACFrame, bodyIn wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields) (wire.SNACMessage, error) {
	ret := _m.Called(ctx, sess, frame, bodyIn)

	if len(ret) == 0 {
		panic("no return value specified for SetUserInfoFields")
	}

	var r0 wire.SNACMessage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *state.Session, wire.SNACFrame, wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields) (wire.SNACMessage, error)); ok {
		return rf(ctx, sess, frame, bodyIn)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *state.Session, wire.SNACFrame, wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields) wire.SNACMessage); ok {
		r0 = rf(ctx, sess, frame, bodyIn)
	} else {
		r0 = ret.Get(0).(wire.SNACMessage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, *state.Session, wire.SNACFrame, wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields) error); ok {
		r1 = rf(ctx, sess, frame, bodyIn)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockOServiceBOSService_SetUserInfoFields_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SetUserInfoFields'
type mockOServiceBOSService_SetUserInfoFields_Call struct {
	*mock.Call
}

// SetUserInfoFields is a helper method to define mock.On call
//   - ctx context.Context
//   - sess *state.Session
//   - frame wire.SNACFrame
//   - bodyIn wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields
func (_e *mockOServiceBOSService_Expecter) SetUserInfoFields(ctx interface{}, sess interface{}, frame interface{}, bodyIn interface{}) *mockOServiceBOSService_SetUserInfoFields_Call {
	return &mockOServiceBOSService_SetUserInfoFields_Call{Call: _e.mock.On("SetUserInfoFields", ctx, sess, frame, bodyIn)}
}

func (_c *mockOServiceBOSService_SetUserInfoFields_Call) Run(run func(ctx context.Context, sess *state.Session, frame wire.SNACFrame, bodyIn wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields)) *mockOServiceBOSService_SetUserInfoFields_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*state.Session), args[2].(wire.SNACFrame), args[3].(wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields))
	})
	return _c
}

func (_c *mockOServiceBOSService_SetUserInfoFields_Call) Return(_a0 wire.SNACMessage, _a1 error) *mockOServiceBOSService_SetUserInfoFields_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockOServiceBOSService_SetUserInfoFields_Call) RunAndReturn(run func(context.Context, *state.Session, wire.SNACFrame, wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields) (wire.SNACMessage, error)) *mockOServiceBOSService_SetUserInfoFields_Call {
	_c.Call.Return(run)
	return _c
}

// UserInfoQuery provides a mock function with given fields: ctx, sess, frame
func (_m *mockOServiceBOSService) UserInfoQuery(ctx context.Context, sess *state.Session, frame wire.SNACFrame) wire.SNACMessage {
	ret := _m.Called(ctx, sess, frame)

	if len(ret) == 0 {
		panic("no return value specified for UserInfoQuery")
	}

	var r0 wire.SNACMessage
	if rf, ok := ret.Get(0).(func(context.Context, *state.Session, wire.SNACFrame) wire.SNACMessage); ok {
		r0 = rf(ctx, sess, frame)
	} else {
		r0 = ret.Get(0).(wire.SNACMessage)
	}

	return r0
}

// mockOServiceBOSService_UserInfoQuery_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UserInfoQuery'
type mockOServiceBOSService_UserInfoQuery_Call struct {
	*mock.Call
}

// UserInfoQuery is a helper method to define mock.On call
//   - ctx context.Context
//   - sess *state.Session
//   - frame wire.SNACFrame
func (_e *mockOServiceBOSService_Expecter) UserInfoQuery(ctx interface{}, sess interface{}, frame interface{}) *mockOServiceBOSService_UserInfoQuery_Call {
	return &mockOServiceBOSService_UserInfoQuery_Call{Call: _e.mock.On("UserInfoQuery", ctx, sess, frame)}
}

func (_c *mockOServiceBOSService_UserInfoQuery_Call) Run(run func(ctx context.Context, sess *state.Session, frame wire.SNACFrame)) *mockOServiceBOSService_UserInfoQuery_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*state.Session), args[2].(wire.SNACFrame))
	})
	return _c
}

func (_c *mockOServiceBOSService_UserInfoQuery_Call) Return(_a0 wire.SNACMessage) *mockOServiceBOSService_UserInfoQuery_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockOServiceBOSService_UserInfoQuery_Call) RunAndReturn(run func(context.Context, *state.Session, wire.SNACFrame) wire.SNACMessage) *mockOServiceBOSService_UserInfoQuery_Call {
	_c.Call.Return(run)
	return _c
}

// newMockOServiceBOSService creates a new instance of mockOServiceBOSService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newMockOServiceBOSService(t interface {
	mock.TestingT
	Cleanup(func())
}) *mockOServiceBOSService {
	mock := &mockOServiceBOSService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}