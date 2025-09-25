module github.com/wispberry-tech/wispy-auth/extensions/referrals/example

go 1.24.6

replace github.com/wispberry-tech/wispy-auth/core => ../../../core
replace github.com/wispberry-tech/wispy-auth/extensions/referrals => ../

require (
	github.com/wispberry-tech/wispy-auth/core v0.0.0-00010101000000-000000000000
	github.com/wispberry-tech/wispy-auth/extensions/referrals v0.0.0-00010101000000-000000000000
)