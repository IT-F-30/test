package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	upnp "github.com/NebulousLabs/go-upnp"
)

func rootHandler(addr string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		res := map[string]string{
			"ipaddr": addr,
		}
		json.NewEncoder(w).Encode(res)
	}
}

// downloadHandler serves files from the ./files directory.
// URL: /files/<filename>
func downloadHandler(baseDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// expected path: /files/<filename>
		p := strings.TrimPrefix(r.URL.Path, "/files/")
		if p == "" || strings.Contains(p, "..") {
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}
		// build absolute path
		fp := filepath.Join(baseDir, filepath.Clean(p))
		f, err := os.Open(fp)
		if err != nil {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		defer f.Close()

		// set headers so curl -O or -J will save with original filename
		w.Header().Set("Content-Type", "application/octet-stream")
		cd := fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(fp))
		w.Header().Set("Content-Disposition", cd)

		http.ServeContent(w, r, filepath.Base(fp), fileModTime(f), f)
	}
}

// fileModTime returns the modification time of the file or zero time on error
func fileModTime(f *os.File) (t time.Time) {
	fi, err := f.Stat()
	if err != nil {
		return
	}
	return fi.ModTime()
}

func main() {

	// Get the local IP address
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatalf("failed to get IP addresses: %v", err)
	}

	var localIP string
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			localIP = ipNet.IP.String()
			break
		}
	}

	if localIP == "" {
		log.Fatalf("could not determine local IP address")
	}

	// Write the IP address to ip.txt
	ipFile := "ip.txt"
	if err := os.WriteFile(ipFile, []byte(localIP), 0644); err != nil {
		log.Fatalf("failed to write IP address to file: %v", err)
	}

	log.Printf("local IP address written to %s", ipFile)

	ln, err := net.Listen("tcp", ":49152")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	addr := ln.Addr().String()
	defer ln.Close()

	// Try UPnP port mapping so the server can be reached from outside the LAN.
	// If mapping fails, we only log instructions for manual port forwarding.
	var gateway *upnp.IGD
	var extAddr string
	portParts := strings.Split(addr, ":")
	port := 49152
	if len(portParts) > 1 {
		// parse the port part
		// ignore parse error and keep default
		fmt.Sscanf(portParts[len(portParts)-1], "%d", &port)
	}

	gateway, err = upnp.Discover()
	if err != nil {
		log.Printf("UPnP discovery failed: %v", err)
		log.Printf("If you need external access, please forward TCP port %d to this machine (%s) in your router settings.", port, localIP)
	} else {
		// Attempt to forward the port (for both TCP and UDP per package behavior)
		if err := gateway.Forward(uint16(port), fmt.Sprintf("http server %d", port)); err != nil {
			log.Printf("failed to add port mapping: %v", err)
			log.Printf("Please forward TCP port %d to %s manually.", port, localIP)
		} else {
			if ea, err := gateway.ExternalIP(); err == nil {
				extAddr = ea
			} else {
				log.Printf("could not get external IP: %v", err)
			}
			log.Printf("UPnP port mapping added: external %s:%d -> %s:%d", extAddr, port, localIP, port)
			// ensure we remove mapping on exit
			defer func() {
				if err := gateway.Clear(uint16(port)); err != nil {
					log.Printf("failed to remove port mapping: %v", err)
				} else {
					log.Printf("removed UPnP port mapping for port %d", port)
				}
			}()
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler(addr))
	// serve downloads from ./files
	mux.HandleFunc("/files/", downloadHandler("./files"))

	srv := &http.Server{
		Handler: mux,
	}

	log.Printf("server listening on http://%s", addr)
	// serve using the obtained listener
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
