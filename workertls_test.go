package goworker

import (
	"crypto/x509"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/garyburd/redigo/redis"
	"github.com/kabukky/httpscerts"
	"github.com/ory/dockertest"
)

func TestRedisTLSIgnoreCertCheck(t *testing.T) {
	manageTLSSetup(t, true)
}

func TestRedisTLSEnforceCertCheck(t *testing.T) {
	manageTLSSetup(t, false)
}

func manageTLSSetup(t *testing.T, skipTLS bool) {
	teardownRedis, redisPort := setupRedisContainer(t)
	defer teardownRedis(t)
	expectedArgs := []interface{}{"my", "word", "is", "my", "bond"}
	jobName := "Worker::Queue"
	queueName := "testqueue"
	expectedJob := &Job{
		Queue: queueName,
		Payload: Payload{
			Class: jobName,
			Args:  expectedArgs,
		},
	}
	settings := WorkerSettings{
		URI:            fmt.Sprintf("rediss://localhost:%s", redisPort),
		ExitOnComplete: true,
		Queues:         []string{queueName},
		SkipTLSVerify:  skipTLS,
		Connections:    1,
		Concurrency:    1,
		UseNumber:      true,
	}
	if !skipTLS {
		settings.TLSCertPath = "./cert.pem"
	}
	SetSettings(settings)
	err := Enqueue(expectedJob)
	if err != nil {
		t.Errorf("Error while enqueue %s", err)
	}

	actualArgs := []interface{}{}
	actualQueueName := ""
	Register(jobName, func(queue string, args ...interface{}) error {
		actualArgs = args
		actualQueueName = queue
		return nil
	})
	if err = Work(); err != nil {
		t.Errorf("(Enqueue) Failed on work %s", err)
	}
	if !reflect.DeepEqual(actualArgs, expectedArgs) {
		t.Errorf("(Enqueue) Expected %v, actual %v", actualArgs, expectedArgs)
	}
	if !reflect.DeepEqual(actualQueueName, queueName) {
		t.Errorf("(Enqueue) Expected %v, actual %v", actualQueueName, queueName)
	}
}

func TestRedisTLSCertCheck(t *testing.T) {
	teardownRedis, redisPort := setupRedisContainer(t)
	defer teardownRedis(t)
	expectedJob := &Job{}
	settings := WorkerSettings{
		URI:            fmt.Sprintf("rediss://localhost:%s", redisPort),
		ExitOnComplete: true,
		SkipTLSVerify:  false,
		Queues:         []string{"testqueue"},
		Connections:    1,
		UseNumber:      true,
		Concurrency:    1,
		Namespace:      "resque:",
		Interval:       5.0,
	}
	SetSettings(settings)
	err := Enqueue(expectedJob)
	if _, ok := err.(x509.UnknownAuthorityError); !ok {
		t.Errorf("Expected an x509 error but received %s", err)
	}
}

func setupRedisContainer(t *testing.T) (func(t *testing.T), string) {
	httpscerts.Generate("cert.pem", "key.pem", "localhost")
	wd, _ := os.Getwd()
	options := &dockertest.RunOptions{
		Repository: "madflojo/redis-tls",
		Tag:        "latest",
		Mounts:     []string{fmt.Sprintf("%s:/certs", wd)},
	}
	pool, err := dockertest.NewPool("")
	if err != nil {
		removeTLSFiles()
		t.Log(err.Error())
		t.FailNow()
	}
	resource, err := pool.RunWithOptions(options)
	if err != nil {
		removeTLSFiles()
		t.Log(err.Error())
		t.FailNow()
	}
	if err = pool.Retry(func() error {
		var dialOptions []redis.DialOption
		dialOptions = append(dialOptions, redis.DialUseTLS(true))
		dialOptions = append(dialOptions, redis.DialTLSSkipVerify(true))
		conn, dialerr := redis.Dial("tcp", fmt.Sprintf("localhost:%s", resource.GetPort("6379/tcp")), dialOptions...)
		if dialerr != nil {
			return dialerr
		}
		conn.Close()
		return nil
	}); err != nil {
		t.Log("Error waiting for Docker image to start.")
		pool.Purge(resource)
		removeTLSFiles()
		t.FailNow()
	}
	return func(t *testing.T) {
		pool.Purge(resource)
		removeTLSFiles()
	}, resource.GetPort("6379/tcp")
}

func removeTLSFiles() {
	os.Remove("cert.pem")
	os.Remove("key.pem")
}
