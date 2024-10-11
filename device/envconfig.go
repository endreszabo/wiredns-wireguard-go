package device

type EnvConfig struct {
	Domains            string `env:"DOMAINS" envDefault:"opendns.org,ldns.net,vpnho.me"`
	RedisServers       string `env:"REDIS_SERVERS_ADDRESSES" envDefault:"redis:6379"`
	RedisUsername      string `env:"REDIS_USERNAME"`
	RedisPassword      string `env:"REDIS_PASSWORD,file"`
	StrayServerAddress string `env:"STRAY_SERVER_ADDRESS" envDefault:"strayserver:3334"`
	StrayRecordTtl     string `env:"STRAY_RECORD_TTL" envDefault:"300"`
	StrayRecordExpity  uint32 `env:"STRAY_RECORD_EXPIRY" envDefault:"300"`
	CreateTxtRecords   bool   `env:"STRAY_CREATE_TXT_RECORDS" envDefault:"true"`
	ListenPort         uint16 `env:"WG_LISTEN_PORT" envDefault:"51820"`
	PrivateKey         string `env:"WG_PRIVATE_KEY,required"`
	PromListenAddress  string `env:"PROM_LISTEN_ADDR" envDefault:":9112"`
	GrpcListenAddress  string `env:"GRPC_LISTEN_ADDR" envDefault:":2112"`
	OpenPeering        bool   `env:"OPEN_PEERING_ENABLED" envDefault:"true"`
	PeersCsv           string `env:"WIREDNS_PEERS_CSV"`
}
