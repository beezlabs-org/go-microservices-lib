package casbin

import (
	"fmt"
	pgadapter "github.com/casbin/casbin-pg-adapter"
	"github.com/casbin/casbin/v2"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/go-pg/pg/v10"
	"os"
	"sync"
)

const DefaultTableName = "casbin_rule"

var once sync.Once
var svc *casbinService

type casbinService struct {
	defaultEnforcer *casbin.Enforcer
	adapter         *pgadapter.Adapter
	logger          log.Logger
	confPath        string
}

type Service interface {
	GetDefaultEnforcer() *casbin.Enforcer
	GetNewEnforcer() *casbin.Enforcer
	GetNewFilteredEnforcer(filter interface{}) *casbin.Enforcer
}

func newCasbinService(adapter *pgadapter.Adapter, logger log.Logger, confPath string) Service {
	svc = &casbinService{
		adapter:  adapter,
		logger:   logger,
		confPath: confPath,
	}
	return svc
}

func InitCasbinAndGetEnforcer(dbSource interface{}, logger log.Logger, confPath string) *casbin.Enforcer {
	once.Do(func() {
		_ = level.Info(logger).Log("msg", "Initializing the casbin postgres adapter")
		adaptor, err := pgadapter.NewAdapter(dbSource)
		if err != nil {
			_ = level.Error(logger).Log("exit", err)
			os.Exit(1)
		}
		newCasbinService(adaptor, logger, confPath)
	})
	svc := GetService()
	setDefaultEnforcer(svc.GetNewEnforcer())
	return svc.GetDefaultEnforcer()
}

func InitCasbinAndGetEnforcerWithCustomDB(dbConn string, ruleTable string, logger log.Logger, confPath string) *casbin.Enforcer {
	db, err := getDBConnection(dbConn)
	if err != nil {
		_ = level.Error(logger).Log("exit", err)
		os.Exit(1)
	}
	defer func(db *pg.DB) {
		err := db.Close()
		if err != nil {
			_ = level.Error(logger).Log("exit", err)
			os.Exit(1)
		}
	}(db)
	once.Do(func() {
		_ = level.Info(logger).Log("msg", "Initializing the casbin postgres adapter with custom db and table")
		if ruleTable == "" {
			ruleTable = DefaultTableName
		}
		adaptor, err := pgadapter.NewAdapterByDB(db, pgadapter.WithTableName(ruleTable))
		if err != nil {
			_ = level.Error(logger).Log("exit", err)
			os.Exit(1)
		}
		newCasbinService(adaptor, logger, confPath)
	})
	svc := GetService()
	setDefaultEnforcer(svc.GetNewEnforcer())
	return svc.GetDefaultEnforcer()

}

func GetService() Service {
	return svc
}

func getDBConnection(dbConn string) (*pg.DB, error) {
	var opts *pg.Options
	var err error
	if dbConn != "" {
		opts, err = pg.ParseURL(dbConn)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("invalid db connection string")
	}

	db := pg.Connect(opts)
	return db, nil
}

func setDefaultEnforcer(enforcer *casbin.Enforcer) {
	svc.defaultEnforcer = enforcer
}

func (c casbinService) GetDefaultEnforcer() *casbin.Enforcer {
	return c.defaultEnforcer
}

func (c casbinService) GetNewEnforcer() *casbin.Enforcer {
	enforcer := getEnforcer(c)
	_ = level.Info(c.logger).Log("msg", "Loading policy from database")
	err := enforcer.LoadPolicy()
	if err != nil {
		_ = level.Error(c.logger).Log("exit", err)
		os.Exit(1)
	}
	return enforcer
}

func (c casbinService) GetNewFilteredEnforcer(filter interface{}) *casbin.Enforcer {
	enforcer := getEnforcer(c)
	_ = level.Info(c.logger).Log("msg", "Loading policy from database")
	err := enforcer.LoadFilteredPolicy(filter)
	if err != nil {
		_ = level.Error(c.logger).Log("exit", err)
		os.Exit(1)
	}
	return enforcer
}

func getEnforcer(c casbinService) *casbin.Enforcer {
	_ = level.Info(c.logger).Log("msg", "Initializing the casbin enforcer")
	enforcer, err := casbin.NewEnforcer(c.confPath, c.adapter)
	if err != nil {
		_ = level.Error(c.logger).Log("exit", err)
		os.Exit(1)
	}
	return enforcer
}
