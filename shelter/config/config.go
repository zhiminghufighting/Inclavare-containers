package config

import ()

//config shelter for running style in future or extend purpuse
type ShelterConfig struct {
	version       string
	podInfo       PodInfo
	containerinfo ContainerInfo
	poolinfo      PoolInfo
}
