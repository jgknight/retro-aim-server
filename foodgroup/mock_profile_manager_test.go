// Code generated by mockery v2.53.3. DO NOT EDIT.

package foodgroup

import (
	context "context"

	state "github.com/mk6i/retro-aim-server/state"
	mock "github.com/stretchr/testify/mock"

	wire "github.com/mk6i/retro-aim-server/wire"
)

// mockProfileManager is an autogenerated mock type for the ProfileManager type
type mockProfileManager struct {
	mock.Mock
}

type mockProfileManager_Expecter struct {
	mock *mock.Mock
}

func (_m *mockProfileManager) EXPECT() *mockProfileManager_Expecter {
	return &mockProfileManager_Expecter{mock: &_m.Mock}
}

// FindByAIMEmail provides a mock function with given fields: ctx, email
func (_m *mockProfileManager) FindByAIMEmail(ctx context.Context, email string) (state.User, error) {
	ret := _m.Called(ctx, email)

	if len(ret) == 0 {
		panic("no return value specified for FindByAIMEmail")
	}

	var r0 state.User
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (state.User, error)); ok {
		return rf(ctx, email)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) state.User); ok {
		r0 = rf(ctx, email)
	} else {
		r0 = ret.Get(0).(state.User)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockProfileManager_FindByAIMEmail_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindByAIMEmail'
type mockProfileManager_FindByAIMEmail_Call struct {
	*mock.Call
}

// FindByAIMEmail is a helper method to define mock.On call
//   - ctx context.Context
//   - email string
func (_e *mockProfileManager_Expecter) FindByAIMEmail(ctx interface{}, email interface{}) *mockProfileManager_FindByAIMEmail_Call {
	return &mockProfileManager_FindByAIMEmail_Call{Call: _e.mock.On("FindByAIMEmail", ctx, email)}
}

func (_c *mockProfileManager_FindByAIMEmail_Call) Run(run func(ctx context.Context, email string)) *mockProfileManager_FindByAIMEmail_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *mockProfileManager_FindByAIMEmail_Call) Return(_a0 state.User, _a1 error) *mockProfileManager_FindByAIMEmail_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockProfileManager_FindByAIMEmail_Call) RunAndReturn(run func(context.Context, string) (state.User, error)) *mockProfileManager_FindByAIMEmail_Call {
	_c.Call.Return(run)
	return _c
}

// FindByAIMKeyword provides a mock function with given fields: ctx, keyword
func (_m *mockProfileManager) FindByAIMKeyword(ctx context.Context, keyword string) ([]state.User, error) {
	ret := _m.Called(ctx, keyword)

	if len(ret) == 0 {
		panic("no return value specified for FindByAIMKeyword")
	}

	var r0 []state.User
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) ([]state.User, error)); ok {
		return rf(ctx, keyword)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) []state.User); ok {
		r0 = rf(ctx, keyword)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]state.User)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, keyword)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockProfileManager_FindByAIMKeyword_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindByAIMKeyword'
type mockProfileManager_FindByAIMKeyword_Call struct {
	*mock.Call
}

// FindByAIMKeyword is a helper method to define mock.On call
//   - ctx context.Context
//   - keyword string
func (_e *mockProfileManager_Expecter) FindByAIMKeyword(ctx interface{}, keyword interface{}) *mockProfileManager_FindByAIMKeyword_Call {
	return &mockProfileManager_FindByAIMKeyword_Call{Call: _e.mock.On("FindByAIMKeyword", ctx, keyword)}
}

func (_c *mockProfileManager_FindByAIMKeyword_Call) Run(run func(ctx context.Context, keyword string)) *mockProfileManager_FindByAIMKeyword_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *mockProfileManager_FindByAIMKeyword_Call) Return(_a0 []state.User, _a1 error) *mockProfileManager_FindByAIMKeyword_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockProfileManager_FindByAIMKeyword_Call) RunAndReturn(run func(context.Context, string) ([]state.User, error)) *mockProfileManager_FindByAIMKeyword_Call {
	_c.Call.Return(run)
	return _c
}

// FindByAIMNameAndAddr provides a mock function with given fields: ctx, info
func (_m *mockProfileManager) FindByAIMNameAndAddr(ctx context.Context, info state.AIMNameAndAddr) ([]state.User, error) {
	ret := _m.Called(ctx, info)

	if len(ret) == 0 {
		panic("no return value specified for FindByAIMNameAndAddr")
	}

	var r0 []state.User
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, state.AIMNameAndAddr) ([]state.User, error)); ok {
		return rf(ctx, info)
	}
	if rf, ok := ret.Get(0).(func(context.Context, state.AIMNameAndAddr) []state.User); ok {
		r0 = rf(ctx, info)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]state.User)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, state.AIMNameAndAddr) error); ok {
		r1 = rf(ctx, info)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockProfileManager_FindByAIMNameAndAddr_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindByAIMNameAndAddr'
type mockProfileManager_FindByAIMNameAndAddr_Call struct {
	*mock.Call
}

// FindByAIMNameAndAddr is a helper method to define mock.On call
//   - ctx context.Context
//   - info state.AIMNameAndAddr
func (_e *mockProfileManager_Expecter) FindByAIMNameAndAddr(ctx interface{}, info interface{}) *mockProfileManager_FindByAIMNameAndAddr_Call {
	return &mockProfileManager_FindByAIMNameAndAddr_Call{Call: _e.mock.On("FindByAIMNameAndAddr", ctx, info)}
}

func (_c *mockProfileManager_FindByAIMNameAndAddr_Call) Run(run func(ctx context.Context, info state.AIMNameAndAddr)) *mockProfileManager_FindByAIMNameAndAddr_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(state.AIMNameAndAddr))
	})
	return _c
}

func (_c *mockProfileManager_FindByAIMNameAndAddr_Call) Return(_a0 []state.User, _a1 error) *mockProfileManager_FindByAIMNameAndAddr_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockProfileManager_FindByAIMNameAndAddr_Call) RunAndReturn(run func(context.Context, state.AIMNameAndAddr) ([]state.User, error)) *mockProfileManager_FindByAIMNameAndAddr_Call {
	_c.Call.Return(run)
	return _c
}

// InterestList provides a mock function with given fields: ctx
func (_m *mockProfileManager) InterestList(ctx context.Context) ([]wire.ODirKeywordListItem, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for InterestList")
	}

	var r0 []wire.ODirKeywordListItem
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) ([]wire.ODirKeywordListItem, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) []wire.ODirKeywordListItem); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]wire.ODirKeywordListItem)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockProfileManager_InterestList_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'InterestList'
type mockProfileManager_InterestList_Call struct {
	*mock.Call
}

// InterestList is a helper method to define mock.On call
//   - ctx context.Context
func (_e *mockProfileManager_Expecter) InterestList(ctx interface{}) *mockProfileManager_InterestList_Call {
	return &mockProfileManager_InterestList_Call{Call: _e.mock.On("InterestList", ctx)}
}

func (_c *mockProfileManager_InterestList_Call) Run(run func(ctx context.Context)) *mockProfileManager_InterestList_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *mockProfileManager_InterestList_Call) Return(_a0 []wire.ODirKeywordListItem, _a1 error) *mockProfileManager_InterestList_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockProfileManager_InterestList_Call) RunAndReturn(run func(context.Context) ([]wire.ODirKeywordListItem, error)) *mockProfileManager_InterestList_Call {
	_c.Call.Return(run)
	return _c
}

// Profile provides a mock function with given fields: ctx, screenName
func (_m *mockProfileManager) Profile(ctx context.Context, screenName state.IdentScreenName) (string, error) {
	ret := _m.Called(ctx, screenName)

	if len(ret) == 0 {
		panic("no return value specified for Profile")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, state.IdentScreenName) (string, error)); ok {
		return rf(ctx, screenName)
	}
	if rf, ok := ret.Get(0).(func(context.Context, state.IdentScreenName) string); ok {
		r0 = rf(ctx, screenName)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, state.IdentScreenName) error); ok {
		r1 = rf(ctx, screenName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockProfileManager_Profile_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Profile'
type mockProfileManager_Profile_Call struct {
	*mock.Call
}

// Profile is a helper method to define mock.On call
//   - ctx context.Context
//   - screenName state.IdentScreenName
func (_e *mockProfileManager_Expecter) Profile(ctx interface{}, screenName interface{}) *mockProfileManager_Profile_Call {
	return &mockProfileManager_Profile_Call{Call: _e.mock.On("Profile", ctx, screenName)}
}

func (_c *mockProfileManager_Profile_Call) Run(run func(ctx context.Context, screenName state.IdentScreenName)) *mockProfileManager_Profile_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(state.IdentScreenName))
	})
	return _c
}

func (_c *mockProfileManager_Profile_Call) Return(_a0 string, _a1 error) *mockProfileManager_Profile_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockProfileManager_Profile_Call) RunAndReturn(run func(context.Context, state.IdentScreenName) (string, error)) *mockProfileManager_Profile_Call {
	_c.Call.Return(run)
	return _c
}

// SetDirectoryInfo provides a mock function with given fields: ctx, screenName, info
func (_m *mockProfileManager) SetDirectoryInfo(ctx context.Context, screenName state.IdentScreenName, info state.AIMNameAndAddr) error {
	ret := _m.Called(ctx, screenName, info)

	if len(ret) == 0 {
		panic("no return value specified for SetDirectoryInfo")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, state.IdentScreenName, state.AIMNameAndAddr) error); ok {
		r0 = rf(ctx, screenName, info)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// mockProfileManager_SetDirectoryInfo_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SetDirectoryInfo'
type mockProfileManager_SetDirectoryInfo_Call struct {
	*mock.Call
}

// SetDirectoryInfo is a helper method to define mock.On call
//   - ctx context.Context
//   - screenName state.IdentScreenName
//   - info state.AIMNameAndAddr
func (_e *mockProfileManager_Expecter) SetDirectoryInfo(ctx interface{}, screenName interface{}, info interface{}) *mockProfileManager_SetDirectoryInfo_Call {
	return &mockProfileManager_SetDirectoryInfo_Call{Call: _e.mock.On("SetDirectoryInfo", ctx, screenName, info)}
}

func (_c *mockProfileManager_SetDirectoryInfo_Call) Run(run func(ctx context.Context, screenName state.IdentScreenName, info state.AIMNameAndAddr)) *mockProfileManager_SetDirectoryInfo_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(state.IdentScreenName), args[2].(state.AIMNameAndAddr))
	})
	return _c
}

func (_c *mockProfileManager_SetDirectoryInfo_Call) Return(_a0 error) *mockProfileManager_SetDirectoryInfo_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockProfileManager_SetDirectoryInfo_Call) RunAndReturn(run func(context.Context, state.IdentScreenName, state.AIMNameAndAddr) error) *mockProfileManager_SetDirectoryInfo_Call {
	_c.Call.Return(run)
	return _c
}

// SetKeywords provides a mock function with given fields: ctx, screenName, keywords
func (_m *mockProfileManager) SetKeywords(ctx context.Context, screenName state.IdentScreenName, keywords [5]string) error {
	ret := _m.Called(ctx, screenName, keywords)

	if len(ret) == 0 {
		panic("no return value specified for SetKeywords")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, state.IdentScreenName, [5]string) error); ok {
		r0 = rf(ctx, screenName, keywords)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// mockProfileManager_SetKeywords_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SetKeywords'
type mockProfileManager_SetKeywords_Call struct {
	*mock.Call
}

// SetKeywords is a helper method to define mock.On call
//   - ctx context.Context
//   - screenName state.IdentScreenName
//   - keywords [5]string
func (_e *mockProfileManager_Expecter) SetKeywords(ctx interface{}, screenName interface{}, keywords interface{}) *mockProfileManager_SetKeywords_Call {
	return &mockProfileManager_SetKeywords_Call{Call: _e.mock.On("SetKeywords", ctx, screenName, keywords)}
}

func (_c *mockProfileManager_SetKeywords_Call) Run(run func(ctx context.Context, screenName state.IdentScreenName, keywords [5]string)) *mockProfileManager_SetKeywords_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(state.IdentScreenName), args[2].([5]string))
	})
	return _c
}

func (_c *mockProfileManager_SetKeywords_Call) Return(_a0 error) *mockProfileManager_SetKeywords_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockProfileManager_SetKeywords_Call) RunAndReturn(run func(context.Context, state.IdentScreenName, [5]string) error) *mockProfileManager_SetKeywords_Call {
	_c.Call.Return(run)
	return _c
}

// SetProfile provides a mock function with given fields: ctx, screenName, body
func (_m *mockProfileManager) SetProfile(ctx context.Context, screenName state.IdentScreenName, body string) error {
	ret := _m.Called(ctx, screenName, body)

	if len(ret) == 0 {
		panic("no return value specified for SetProfile")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, state.IdentScreenName, string) error); ok {
		r0 = rf(ctx, screenName, body)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// mockProfileManager_SetProfile_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SetProfile'
type mockProfileManager_SetProfile_Call struct {
	*mock.Call
}

// SetProfile is a helper method to define mock.On call
//   - ctx context.Context
//   - screenName state.IdentScreenName
//   - body string
func (_e *mockProfileManager_Expecter) SetProfile(ctx interface{}, screenName interface{}, body interface{}) *mockProfileManager_SetProfile_Call {
	return &mockProfileManager_SetProfile_Call{Call: _e.mock.On("SetProfile", ctx, screenName, body)}
}

func (_c *mockProfileManager_SetProfile_Call) Run(run func(ctx context.Context, screenName state.IdentScreenName, body string)) *mockProfileManager_SetProfile_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(state.IdentScreenName), args[2].(string))
	})
	return _c
}

func (_c *mockProfileManager_SetProfile_Call) Return(_a0 error) *mockProfileManager_SetProfile_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockProfileManager_SetProfile_Call) RunAndReturn(run func(context.Context, state.IdentScreenName, string) error) *mockProfileManager_SetProfile_Call {
	_c.Call.Return(run)
	return _c
}

// User provides a mock function with given fields: ctx, screenName
func (_m *mockProfileManager) User(ctx context.Context, screenName state.IdentScreenName) (*state.User, error) {
	ret := _m.Called(ctx, screenName)

	if len(ret) == 0 {
		panic("no return value specified for User")
	}

	var r0 *state.User
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, state.IdentScreenName) (*state.User, error)); ok {
		return rf(ctx, screenName)
	}
	if rf, ok := ret.Get(0).(func(context.Context, state.IdentScreenName) *state.User); ok {
		r0 = rf(ctx, screenName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*state.User)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, state.IdentScreenName) error); ok {
		r1 = rf(ctx, screenName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockProfileManager_User_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'User'
type mockProfileManager_User_Call struct {
	*mock.Call
}

// User is a helper method to define mock.On call
//   - ctx context.Context
//   - screenName state.IdentScreenName
func (_e *mockProfileManager_Expecter) User(ctx interface{}, screenName interface{}) *mockProfileManager_User_Call {
	return &mockProfileManager_User_Call{Call: _e.mock.On("User", ctx, screenName)}
}

func (_c *mockProfileManager_User_Call) Run(run func(ctx context.Context, screenName state.IdentScreenName)) *mockProfileManager_User_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(state.IdentScreenName))
	})
	return _c
}

func (_c *mockProfileManager_User_Call) Return(_a0 *state.User, _a1 error) *mockProfileManager_User_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockProfileManager_User_Call) RunAndReturn(run func(context.Context, state.IdentScreenName) (*state.User, error)) *mockProfileManager_User_Call {
	_c.Call.Return(run)
	return _c
}

// newMockProfileManager creates a new instance of mockProfileManager. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newMockProfileManager(t interface {
	mock.TestingT
	Cleanup(func())
}) *mockProfileManager {
	mock := &mockProfileManager{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
