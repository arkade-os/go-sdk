package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	password = "secret"
	adminUrl = "http://localhost:7071"
)

func main() {
	if err := setupArkd(); err != nil {
		fmt.Printf("failed to setup arkd: %s\n", err)
		os.Exit(1)
	}
	fmt.Println("setup arkd completed")
	os.Exit(0)
}

func setupArkd() error {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	time.Sleep(1 * time.Second)

	fmt.Println("waiting for arkd to be ready...")
	url := fmt.Sprintf("%s/v1/admin/wallet/status", adminUrl)
	status, err := get[statusResp](adminHttpClient, url, "status")
	if err != nil {
		return err
	}

	if status.Initialized && !status.Unlocked {
		url := fmt.Sprintf("%s/v1/admin/wallet/unlock", adminUrl)
		body := fmt.Sprintf(`{"password": "%s"}`, password)
		if err := post(adminHttpClient, url, body, "unlock"); err != nil {
			return err
		}

		if err := waitUntilReady(adminHttpClient); err != nil {
			return err
		}

		return refill(adminHttpClient)
	}

	if status.Initialized && status.Unlocked && status.Synced {
		return refill(adminHttpClient)
	}

	fmt.Println("getting wallet seed...")
	url = fmt.Sprintf("%s/v1/admin/wallet/seed", adminUrl)
	seed, err := get[seedResp](adminHttpClient, url, "seed")
	if err != nil {
		return err
	}

	fmt.Println("creating wallet...")
	url = fmt.Sprintf("%s/v1/admin/wallet/create", adminUrl)
	body := fmt.Sprintf(`{"seed": "%s", "password": "%s"}`, seed.Seed, password)
	if err := post(adminHttpClient, url, body, "create"); err != nil {
		return err
	}

	fmt.Println("unlocking wallet...")
	url = fmt.Sprintf("%s/v1/admin/wallet/unlock", adminUrl)
	body = fmt.Sprintf(`{"password": "%s"}`, password)
	if err := post(adminHttpClient, url, body, "unlock"); err != nil {
		return err
	}

	fmt.Println("waiting for wallet to be synced...")
	if err := waitUntilReady(adminHttpClient); err != nil {
		return err
	}

	return refill(adminHttpClient)
}

type statusResp struct {
	Initialized bool `json:"initialized"`
	Unlocked    bool `json:"unlocked"`
	Synced      bool `json:"synced"`
}
type seedResp struct {
	Seed string `json:"seed"`
}
type addressResp struct {
	Address string `json:"address"`
}
type balanceResp struct {
	MainAccount struct {
		Available float64 `json:"available,string"`
	} `json:"mainAccount"`
}

func get[T any](httpClient *http.Client, url, name string) (*T, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare %s request: %s", name, err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s: %s", name, err)
	}
	var data T
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to parse %s response: %s", name, err)
	}
	return &data, nil
}

func waitUntilReady(httpClient *http.Client) error {
	ticker := time.NewTicker(2 * time.Second)
	url := fmt.Sprintf("%s/v1/admin/wallet/status", adminUrl)
	for range ticker.C {
		status, err := get[statusResp](httpClient, url, "status")
		if err != nil {
			return err
		}

		if status.Initialized && status.Unlocked && status.Synced {
			ticker.Stop()
			break
		}
	}
	return nil
}

func refill(httpClient *http.Client) error {
	url := fmt.Sprintf("%s/v1/admin/wallet/balance", adminUrl)
	balance, err := get[balanceResp](httpClient, url, "balance")
	if err != nil {
		return err
	}

	if delta := 15 - balance.MainAccount.Available; delta > 0 {
		url = fmt.Sprintf("%s/v1/admin/wallet/address", adminUrl)
		address, err := get[addressResp](httpClient, url, "address")
		if err != nil {
			return err
		}

		for range int(delta) {
			if _, err := runCommand("nigiri", "faucet", address.Address); err != nil {
				return err
			}
		}
	}
	return nil
}

func post(httpClient *http.Client, url, body, name string) error {
	req, err := http.NewRequest("POST", url, bytes.NewReader([]byte(body)))
	if err != nil {
		return fmt.Errorf("failed to prepare %s request: %s", name, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if _, err := httpClient.Do(req); err != nil {
		return fmt.Errorf("failed to %s wallet: %s", name, err)
	}
	return nil
}

func runCommand(name string, arg ...string) (string, error) {
	errb := new(strings.Builder)
	cmd := newCommand(name, arg...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}

	if err := cmd.Start(); err != nil {
		return "", err
	}
	output := new(strings.Builder)
	errorb := new(strings.Builder)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(output, stdout); err != nil {
			fmt.Fprintf(errb, "error reading stdout: %s", err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(errorb, stderr); err != nil {
			fmt.Fprintf(errb, "error reading stderr: %s", err)
		}
	}()

	wg.Wait()
	if err := cmd.Wait(); err != nil {
		if errMsg := errorb.String(); len(errMsg) > 0 {
			return "", fmt.Errorf("%s", errMsg)
		}

		if outMsg := output.String(); len(outMsg) > 0 {
			return "", fmt.Errorf("%s", outMsg)
		}

		return "", err
	}

	if errMsg := errb.String(); len(errMsg) > 0 {
		return "", fmt.Errorf("%s", errMsg)
	}

	return strings.Trim(output.String(), "\n"), nil
}

func newCommand(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	return cmd
}
