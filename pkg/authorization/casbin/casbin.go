package casbin

import "github.com/beezlabs-org/go-microservices-lib/internal/authorization/casbin"

var (
	InitCasbinAndGetEnforcer             = casbin.InitCasbinAndGetEnforcer
	InitCasbinAndGetEnforcerWithCustomDB = casbin.InitCasbinAndGetEnforcerWithCustomDB
	GetService                           = casbin.GetService
)
