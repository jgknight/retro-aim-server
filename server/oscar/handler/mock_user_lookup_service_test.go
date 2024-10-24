// Code generated by mockery v2.46.3. DO NOT EDIT.

package handler

import (
	context "context"

	wire "github.com/mk6i/retro-aim-server/wire"
	mock "github.com/stretchr/testify/mock"
)

// mockUserLookupService is an autogenerated mock type for the UserLookupService type
type mockUserLookupService struct {
	mock.Mock
}

type mockUserLookupService_Expecter struct {
	mock *mock.Mock
}

func (_m *mockUserLookupService) EXPECT() *mockUserLookupService_Expecter {
	return &mockUserLookupService_Expecter{mock: &_m.Mock}
}

// FindByEmail provides a mock function with given fields: ctx, inFrame, inBody
func (_m *mockUserLookupService) FindByEmail(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x0A_0x02_UserLookupFindByEmail) (wire.SNACMessage, error) {
	ret := _m.Called(ctx, inFrame, inBody)

	if len(ret) == 0 {
		panic("no return value specified for FindByEmail")
	}

	var r0 wire.SNACMessage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, wire.SNACFrame, wire.SNAC_0x0A_0x02_UserLookupFindByEmail) (wire.SNACMessage, error)); ok {
		return rf(ctx, inFrame, inBody)
	}
	if rf, ok := ret.Get(0).(func(context.Context, wire.SNACFrame, wire.SNAC_0x0A_0x02_UserLookupFindByEmail) wire.SNACMessage); ok {
		r0 = rf(ctx, inFrame, inBody)
	} else {
		r0 = ret.Get(0).(wire.SNACMessage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, wire.SNACFrame, wire.SNAC_0x0A_0x02_UserLookupFindByEmail) error); ok {
		r1 = rf(ctx, inFrame, inBody)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockUserLookupService_FindByEmail_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindByEmail'
type mockUserLookupService_FindByEmail_Call struct {
	*mock.Call
}

// FindByEmail is a helper method to define mock.On call
//   - ctx context.Context
//   - inFrame wire.SNACFrame
//   - inBody wire.SNAC_0x0A_0x02_UserLookupFindByEmail
func (_e *mockUserLookupService_Expecter) FindByEmail(ctx interface{}, inFrame interface{}, inBody interface{}) *mockUserLookupService_FindByEmail_Call {
	return &mockUserLookupService_FindByEmail_Call{Call: _e.mock.On("FindByEmail", ctx, inFrame, inBody)}
}

func (_c *mockUserLookupService_FindByEmail_Call) Run(run func(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x0A_0x02_UserLookupFindByEmail)) *mockUserLookupService_FindByEmail_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(wire.SNACFrame), args[2].(wire.SNAC_0x0A_0x02_UserLookupFindByEmail))
	})
	return _c
}

func (_c *mockUserLookupService_FindByEmail_Call) Return(_a0 wire.SNACMessage, _a1 error) *mockUserLookupService_FindByEmail_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockUserLookupService_FindByEmail_Call) RunAndReturn(run func(context.Context, wire.SNACFrame, wire.SNAC_0x0A_0x02_UserLookupFindByEmail) (wire.SNACMessage, error)) *mockUserLookupService_FindByEmail_Call {
	_c.Call.Return(run)
	return _c
}

// newMockUserLookupService creates a new instance of mockUserLookupService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newMockUserLookupService(t interface {
	mock.TestingT
	Cleanup(func())
}) *mockUserLookupService {
	mock := &mockUserLookupService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
