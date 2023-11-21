// Code generated by mockery v2.34.2. DO NOT EDIT.

package server

import (
	context "context"

	oscar "github.com/mkaminski/goaim/oscar"
	mock "github.com/stretchr/testify/mock"

	state "github.com/mkaminski/goaim/state"
)

// mockOServiceBOSHandler is an autogenerated mock type for the OServiceBOSHandler type
type mockOServiceBOSHandler struct {
	mock.Mock
}

type mockOServiceBOSHandler_Expecter struct {
	mock *mock.Mock
}

func (_m *mockOServiceBOSHandler) EXPECT() *mockOServiceBOSHandler_Expecter {
	return &mockOServiceBOSHandler_Expecter{mock: &_m.Mock}
}

// ClientOnlineHandler provides a mock function with given fields: ctx, snacPayloadIn, sess
func (_m *mockOServiceBOSHandler) ClientOnlineHandler(ctx context.Context, snacPayloadIn oscar.SNAC_0x01_0x02_OServiceClientOnline, sess *state.Session) error {
	ret := _m.Called(ctx, snacPayloadIn, sess)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, oscar.SNAC_0x01_0x02_OServiceClientOnline, *state.Session) error); ok {
		r0 = rf(ctx, snacPayloadIn, sess)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// mockOServiceBOSHandler_ClientOnlineHandler_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ClientOnlineHandler'
type mockOServiceBOSHandler_ClientOnlineHandler_Call struct {
	*mock.Call
}

// ClientOnlineHandler is a helper method to define mock.On call
//   - ctx context.Context
//   - snacPayloadIn oscar.SNAC_0x01_0x02_OServiceClientOnline
//   - sess *state.Session
func (_e *mockOServiceBOSHandler_Expecter) ClientOnlineHandler(ctx interface{}, snacPayloadIn interface{}, sess interface{}) *mockOServiceBOSHandler_ClientOnlineHandler_Call {
	return &mockOServiceBOSHandler_ClientOnlineHandler_Call{Call: _e.mock.On("ClientOnlineHandler", ctx, snacPayloadIn, sess)}
}

func (_c *mockOServiceBOSHandler_ClientOnlineHandler_Call) Run(run func(ctx context.Context, snacPayloadIn oscar.SNAC_0x01_0x02_OServiceClientOnline, sess *state.Session)) *mockOServiceBOSHandler_ClientOnlineHandler_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(oscar.SNAC_0x01_0x02_OServiceClientOnline), args[2].(*state.Session))
	})
	return _c
}

func (_c *mockOServiceBOSHandler_ClientOnlineHandler_Call) Return(_a0 error) *mockOServiceBOSHandler_ClientOnlineHandler_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockOServiceBOSHandler_ClientOnlineHandler_Call) RunAndReturn(run func(context.Context, oscar.SNAC_0x01_0x02_OServiceClientOnline, *state.Session) error) *mockOServiceBOSHandler_ClientOnlineHandler_Call {
	_c.Call.Return(run)
	return _c
}

// ClientVersionsHandler provides a mock function with given fields: ctx, snacPayloadIn
func (_m *mockOServiceBOSHandler) ClientVersionsHandler(ctx context.Context, snacPayloadIn oscar.SNAC_0x01_0x17_OServiceClientVersions) oscar.XMessage {
	ret := _m.Called(ctx, snacPayloadIn)

	var r0 oscar.XMessage
	if rf, ok := ret.Get(0).(func(context.Context, oscar.SNAC_0x01_0x17_OServiceClientVersions) oscar.XMessage); ok {
		r0 = rf(ctx, snacPayloadIn)
	} else {
		r0 = ret.Get(0).(oscar.XMessage)
	}

	return r0
}

// mockOServiceBOSHandler_ClientVersionsHandler_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ClientVersionsHandler'
type mockOServiceBOSHandler_ClientVersionsHandler_Call struct {
	*mock.Call
}

// ClientVersionsHandler is a helper method to define mock.On call
//   - ctx context.Context
//   - snacPayloadIn oscar.SNAC_0x01_0x17_OServiceClientVersions
func (_e *mockOServiceBOSHandler_Expecter) ClientVersionsHandler(ctx interface{}, snacPayloadIn interface{}) *mockOServiceBOSHandler_ClientVersionsHandler_Call {
	return &mockOServiceBOSHandler_ClientVersionsHandler_Call{Call: _e.mock.On("ClientVersionsHandler", ctx, snacPayloadIn)}
}

func (_c *mockOServiceBOSHandler_ClientVersionsHandler_Call) Run(run func(ctx context.Context, snacPayloadIn oscar.SNAC_0x01_0x17_OServiceClientVersions)) *mockOServiceBOSHandler_ClientVersionsHandler_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(oscar.SNAC_0x01_0x17_OServiceClientVersions))
	})
	return _c
}

func (_c *mockOServiceBOSHandler_ClientVersionsHandler_Call) Return(_a0 oscar.XMessage) *mockOServiceBOSHandler_ClientVersionsHandler_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockOServiceBOSHandler_ClientVersionsHandler_Call) RunAndReturn(run func(context.Context, oscar.SNAC_0x01_0x17_OServiceClientVersions) oscar.XMessage) *mockOServiceBOSHandler_ClientVersionsHandler_Call {
	_c.Call.Return(run)
	return _c
}

// IdleNotificationHandler provides a mock function with given fields: ctx, sess, snacPayloadIn
func (_m *mockOServiceBOSHandler) IdleNotificationHandler(ctx context.Context, sess *state.Session, snacPayloadIn oscar.SNAC_0x01_0x11_OServiceIdleNotification) error {
	ret := _m.Called(ctx, sess, snacPayloadIn)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *state.Session, oscar.SNAC_0x01_0x11_OServiceIdleNotification) error); ok {
		r0 = rf(ctx, sess, snacPayloadIn)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// mockOServiceBOSHandler_IdleNotificationHandler_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IdleNotificationHandler'
type mockOServiceBOSHandler_IdleNotificationHandler_Call struct {
	*mock.Call
}

// IdleNotificationHandler is a helper method to define mock.On call
//   - ctx context.Context
//   - sess *state.Session
//   - snacPayloadIn oscar.SNAC_0x01_0x11_OServiceIdleNotification
func (_e *mockOServiceBOSHandler_Expecter) IdleNotificationHandler(ctx interface{}, sess interface{}, snacPayloadIn interface{}) *mockOServiceBOSHandler_IdleNotificationHandler_Call {
	return &mockOServiceBOSHandler_IdleNotificationHandler_Call{Call: _e.mock.On("IdleNotificationHandler", ctx, sess, snacPayloadIn)}
}

func (_c *mockOServiceBOSHandler_IdleNotificationHandler_Call) Run(run func(ctx context.Context, sess *state.Session, snacPayloadIn oscar.SNAC_0x01_0x11_OServiceIdleNotification)) *mockOServiceBOSHandler_IdleNotificationHandler_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*state.Session), args[2].(oscar.SNAC_0x01_0x11_OServiceIdleNotification))
	})
	return _c
}

func (_c *mockOServiceBOSHandler_IdleNotificationHandler_Call) Return(_a0 error) *mockOServiceBOSHandler_IdleNotificationHandler_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockOServiceBOSHandler_IdleNotificationHandler_Call) RunAndReturn(run func(context.Context, *state.Session, oscar.SNAC_0x01_0x11_OServiceIdleNotification) error) *mockOServiceBOSHandler_IdleNotificationHandler_Call {
	_c.Call.Return(run)
	return _c
}

// RateParamsQueryHandler provides a mock function with given fields: ctx
func (_m *mockOServiceBOSHandler) RateParamsQueryHandler(ctx context.Context) oscar.XMessage {
	ret := _m.Called(ctx)

	var r0 oscar.XMessage
	if rf, ok := ret.Get(0).(func(context.Context) oscar.XMessage); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(oscar.XMessage)
	}

	return r0
}

// mockOServiceBOSHandler_RateParamsQueryHandler_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RateParamsQueryHandler'
type mockOServiceBOSHandler_RateParamsQueryHandler_Call struct {
	*mock.Call
}

// RateParamsQueryHandler is a helper method to define mock.On call
//   - ctx context.Context
func (_e *mockOServiceBOSHandler_Expecter) RateParamsQueryHandler(ctx interface{}) *mockOServiceBOSHandler_RateParamsQueryHandler_Call {
	return &mockOServiceBOSHandler_RateParamsQueryHandler_Call{Call: _e.mock.On("RateParamsQueryHandler", ctx)}
}

func (_c *mockOServiceBOSHandler_RateParamsQueryHandler_Call) Run(run func(ctx context.Context)) *mockOServiceBOSHandler_RateParamsQueryHandler_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *mockOServiceBOSHandler_RateParamsQueryHandler_Call) Return(_a0 oscar.XMessage) *mockOServiceBOSHandler_RateParamsQueryHandler_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockOServiceBOSHandler_RateParamsQueryHandler_Call) RunAndReturn(run func(context.Context) oscar.XMessage) *mockOServiceBOSHandler_RateParamsQueryHandler_Call {
	_c.Call.Return(run)
	return _c
}

// RateParamsSubAddHandler provides a mock function with given fields: _a0, _a1
func (_m *mockOServiceBOSHandler) RateParamsSubAddHandler(_a0 context.Context, _a1 oscar.SNAC_0x01_0x08_OServiceRateParamsSubAdd) {
	_m.Called(_a0, _a1)
}

// mockOServiceBOSHandler_RateParamsSubAddHandler_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RateParamsSubAddHandler'
type mockOServiceBOSHandler_RateParamsSubAddHandler_Call struct {
	*mock.Call
}

// RateParamsSubAddHandler is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 oscar.SNAC_0x01_0x08_OServiceRateParamsSubAdd
func (_e *mockOServiceBOSHandler_Expecter) RateParamsSubAddHandler(_a0 interface{}, _a1 interface{}) *mockOServiceBOSHandler_RateParamsSubAddHandler_Call {
	return &mockOServiceBOSHandler_RateParamsSubAddHandler_Call{Call: _e.mock.On("RateParamsSubAddHandler", _a0, _a1)}
}

func (_c *mockOServiceBOSHandler_RateParamsSubAddHandler_Call) Run(run func(_a0 context.Context, _a1 oscar.SNAC_0x01_0x08_OServiceRateParamsSubAdd)) *mockOServiceBOSHandler_RateParamsSubAddHandler_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(oscar.SNAC_0x01_0x08_OServiceRateParamsSubAdd))
	})
	return _c
}

func (_c *mockOServiceBOSHandler_RateParamsSubAddHandler_Call) Return() *mockOServiceBOSHandler_RateParamsSubAddHandler_Call {
	_c.Call.Return()
	return _c
}

func (_c *mockOServiceBOSHandler_RateParamsSubAddHandler_Call) RunAndReturn(run func(context.Context, oscar.SNAC_0x01_0x08_OServiceRateParamsSubAdd)) *mockOServiceBOSHandler_RateParamsSubAddHandler_Call {
	_c.Call.Return(run)
	return _c
}

// ServiceRequestHandler provides a mock function with given fields: ctx, sess, snacPayloadIn
func (_m *mockOServiceBOSHandler) ServiceRequestHandler(ctx context.Context, sess *state.Session, snacPayloadIn oscar.SNAC_0x01_0x04_OServiceServiceRequest) (oscar.XMessage, error) {
	ret := _m.Called(ctx, sess, snacPayloadIn)

	var r0 oscar.XMessage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *state.Session, oscar.SNAC_0x01_0x04_OServiceServiceRequest) (oscar.XMessage, error)); ok {
		return rf(ctx, sess, snacPayloadIn)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *state.Session, oscar.SNAC_0x01_0x04_OServiceServiceRequest) oscar.XMessage); ok {
		r0 = rf(ctx, sess, snacPayloadIn)
	} else {
		r0 = ret.Get(0).(oscar.XMessage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, *state.Session, oscar.SNAC_0x01_0x04_OServiceServiceRequest) error); ok {
		r1 = rf(ctx, sess, snacPayloadIn)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockOServiceBOSHandler_ServiceRequestHandler_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ServiceRequestHandler'
type mockOServiceBOSHandler_ServiceRequestHandler_Call struct {
	*mock.Call
}

// ServiceRequestHandler is a helper method to define mock.On call
//   - ctx context.Context
//   - sess *state.Session
//   - snacPayloadIn oscar.SNAC_0x01_0x04_OServiceServiceRequest
func (_e *mockOServiceBOSHandler_Expecter) ServiceRequestHandler(ctx interface{}, sess interface{}, snacPayloadIn interface{}) *mockOServiceBOSHandler_ServiceRequestHandler_Call {
	return &mockOServiceBOSHandler_ServiceRequestHandler_Call{Call: _e.mock.On("ServiceRequestHandler", ctx, sess, snacPayloadIn)}
}

func (_c *mockOServiceBOSHandler_ServiceRequestHandler_Call) Run(run func(ctx context.Context, sess *state.Session, snacPayloadIn oscar.SNAC_0x01_0x04_OServiceServiceRequest)) *mockOServiceBOSHandler_ServiceRequestHandler_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*state.Session), args[2].(oscar.SNAC_0x01_0x04_OServiceServiceRequest))
	})
	return _c
}

func (_c *mockOServiceBOSHandler_ServiceRequestHandler_Call) Return(_a0 oscar.XMessage, _a1 error) *mockOServiceBOSHandler_ServiceRequestHandler_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockOServiceBOSHandler_ServiceRequestHandler_Call) RunAndReturn(run func(context.Context, *state.Session, oscar.SNAC_0x01_0x04_OServiceServiceRequest) (oscar.XMessage, error)) *mockOServiceBOSHandler_ServiceRequestHandler_Call {
	_c.Call.Return(run)
	return _c
}

// SetUserInfoFieldsHandler provides a mock function with given fields: ctx, sess, snacPayloadIn
func (_m *mockOServiceBOSHandler) SetUserInfoFieldsHandler(ctx context.Context, sess *state.Session, snacPayloadIn oscar.SNAC_0x01_0x1E_OServiceSetUserInfoFields) (oscar.XMessage, error) {
	ret := _m.Called(ctx, sess, snacPayloadIn)

	var r0 oscar.XMessage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *state.Session, oscar.SNAC_0x01_0x1E_OServiceSetUserInfoFields) (oscar.XMessage, error)); ok {
		return rf(ctx, sess, snacPayloadIn)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *state.Session, oscar.SNAC_0x01_0x1E_OServiceSetUserInfoFields) oscar.XMessage); ok {
		r0 = rf(ctx, sess, snacPayloadIn)
	} else {
		r0 = ret.Get(0).(oscar.XMessage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, *state.Session, oscar.SNAC_0x01_0x1E_OServiceSetUserInfoFields) error); ok {
		r1 = rf(ctx, sess, snacPayloadIn)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockOServiceBOSHandler_SetUserInfoFieldsHandler_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SetUserInfoFieldsHandler'
type mockOServiceBOSHandler_SetUserInfoFieldsHandler_Call struct {
	*mock.Call
}

// SetUserInfoFieldsHandler is a helper method to define mock.On call
//   - ctx context.Context
//   - sess *state.Session
//   - snacPayloadIn oscar.SNAC_0x01_0x1E_OServiceSetUserInfoFields
func (_e *mockOServiceBOSHandler_Expecter) SetUserInfoFieldsHandler(ctx interface{}, sess interface{}, snacPayloadIn interface{}) *mockOServiceBOSHandler_SetUserInfoFieldsHandler_Call {
	return &mockOServiceBOSHandler_SetUserInfoFieldsHandler_Call{Call: _e.mock.On("SetUserInfoFieldsHandler", ctx, sess, snacPayloadIn)}
}

func (_c *mockOServiceBOSHandler_SetUserInfoFieldsHandler_Call) Run(run func(ctx context.Context, sess *state.Session, snacPayloadIn oscar.SNAC_0x01_0x1E_OServiceSetUserInfoFields)) *mockOServiceBOSHandler_SetUserInfoFieldsHandler_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*state.Session), args[2].(oscar.SNAC_0x01_0x1E_OServiceSetUserInfoFields))
	})
	return _c
}

func (_c *mockOServiceBOSHandler_SetUserInfoFieldsHandler_Call) Return(_a0 oscar.XMessage, _a1 error) *mockOServiceBOSHandler_SetUserInfoFieldsHandler_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockOServiceBOSHandler_SetUserInfoFieldsHandler_Call) RunAndReturn(run func(context.Context, *state.Session, oscar.SNAC_0x01_0x1E_OServiceSetUserInfoFields) (oscar.XMessage, error)) *mockOServiceBOSHandler_SetUserInfoFieldsHandler_Call {
	_c.Call.Return(run)
	return _c
}

// UserInfoQueryHandler provides a mock function with given fields: ctx, sess
func (_m *mockOServiceBOSHandler) UserInfoQueryHandler(ctx context.Context, sess *state.Session) oscar.XMessage {
	ret := _m.Called(ctx, sess)

	var r0 oscar.XMessage
	if rf, ok := ret.Get(0).(func(context.Context, *state.Session) oscar.XMessage); ok {
		r0 = rf(ctx, sess)
	} else {
		r0 = ret.Get(0).(oscar.XMessage)
	}

	return r0
}

// mockOServiceBOSHandler_UserInfoQueryHandler_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UserInfoQueryHandler'
type mockOServiceBOSHandler_UserInfoQueryHandler_Call struct {
	*mock.Call
}

// UserInfoQueryHandler is a helper method to define mock.On call
//   - ctx context.Context
//   - sess *state.Session
func (_e *mockOServiceBOSHandler_Expecter) UserInfoQueryHandler(ctx interface{}, sess interface{}) *mockOServiceBOSHandler_UserInfoQueryHandler_Call {
	return &mockOServiceBOSHandler_UserInfoQueryHandler_Call{Call: _e.mock.On("UserInfoQueryHandler", ctx, sess)}
}

func (_c *mockOServiceBOSHandler_UserInfoQueryHandler_Call) Run(run func(ctx context.Context, sess *state.Session)) *mockOServiceBOSHandler_UserInfoQueryHandler_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*state.Session))
	})
	return _c
}

func (_c *mockOServiceBOSHandler_UserInfoQueryHandler_Call) Return(_a0 oscar.XMessage) *mockOServiceBOSHandler_UserInfoQueryHandler_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockOServiceBOSHandler_UserInfoQueryHandler_Call) RunAndReturn(run func(context.Context, *state.Session) oscar.XMessage) *mockOServiceBOSHandler_UserInfoQueryHandler_Call {
	_c.Call.Return(run)
	return _c
}

// WriteOServiceHostOnline provides a mock function with given fields:
func (_m *mockOServiceBOSHandler) WriteOServiceHostOnline() oscar.XMessage {
	ret := _m.Called()

	var r0 oscar.XMessage
	if rf, ok := ret.Get(0).(func() oscar.XMessage); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(oscar.XMessage)
	}

	return r0
}

// mockOServiceBOSHandler_WriteOServiceHostOnline_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'WriteOServiceHostOnline'
type mockOServiceBOSHandler_WriteOServiceHostOnline_Call struct {
	*mock.Call
}

// WriteOServiceHostOnline is a helper method to define mock.On call
func (_e *mockOServiceBOSHandler_Expecter) WriteOServiceHostOnline() *mockOServiceBOSHandler_WriteOServiceHostOnline_Call {
	return &mockOServiceBOSHandler_WriteOServiceHostOnline_Call{Call: _e.mock.On("WriteOServiceHostOnline")}
}

func (_c *mockOServiceBOSHandler_WriteOServiceHostOnline_Call) Run(run func()) *mockOServiceBOSHandler_WriteOServiceHostOnline_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *mockOServiceBOSHandler_WriteOServiceHostOnline_Call) Return(_a0 oscar.XMessage) *mockOServiceBOSHandler_WriteOServiceHostOnline_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockOServiceBOSHandler_WriteOServiceHostOnline_Call) RunAndReturn(run func() oscar.XMessage) *mockOServiceBOSHandler_WriteOServiceHostOnline_Call {
	_c.Call.Return(run)
	return _c
}

// newMockOServiceBOSHandler creates a new instance of mockOServiceBOSHandler. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newMockOServiceBOSHandler(t interface {
	mock.TestingT
	Cleanup(func())
}) *mockOServiceBOSHandler {
	mock := &mockOServiceBOSHandler{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
