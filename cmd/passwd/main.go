// cmd/passwd - utility to change a user's password in the database
// Usage:
//
//	go run ./cmd/passwd --email admin@example.com --password newpass123
//	go run ./cmd/passwd --username admin
//	./passwd --email user@demolocal.online --password secret
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	"gotunnel/internal/auth"
	"gotunnel/internal/database"
	"gotunnel/internal/server"

	"golang.org/x/term"
)

func main() {
	var (
		email    = flag.String("email", "", "Email user yang akan diubah passwordnya")
		username = flag.String("username", "", "Username user yang akan diubah passwordnya")
		password = flag.String("password", "", "Password baru (jika tidak diisi, akan diminta secara interaktif)")
		envFile  = flag.String("env", ".env", "Path ke file .env (default: .env)")
	)
	flag.Parse()

	if *email == "" && *username == "" {
		fmt.Fprintln(os.Stderr, "Error: --email atau --username harus diisi")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Contoh penggunaan:")
		fmt.Fprintln(os.Stderr, "  go run ./cmd/passwd --email admin@demolocal.online --password rahasia123")
		fmt.Fprintln(os.Stderr, "  go run ./cmd/passwd --username admin")
		os.Exit(1)
	}

	// Load .env
	server.LoadDotEnv(*envFile)

	// Connect database
	db, err := database.New()
	if err != nil {
		log.Fatalf("Gagal koneksi database: %v", err)
	}
	defer db.Close()

	// Cari user
	var user interface{ GetID() int64 }
	if *email != "" {
		u, err := db.GetUserByEmail(*email)
		if err != nil {
			log.Fatalf("User dengan email '%s' tidak ditemukan: %v", *email, err)
		}
		fmt.Printf("User ditemukan: %s (%s)\n", u.Username, u.Email)
		// Dapatkan password baru
		newHash, err := getAndHashPassword(*password)
		if err != nil {
			log.Fatalf("Gagal memproses password: %v", err)
		}
		if err := db.UpdateUserPassword(u.ID, newHash); err != nil {
			log.Fatalf("Gagal mengubah password: %v", err)
		}
		_ = user
	} else {
		u, err := db.GetUserByUsername(*username)
		if err != nil {
			log.Fatalf("User dengan username '%s' tidak ditemukan: %v", *username, err)
		}
		fmt.Printf("User ditemukan: %s (%s)\n", u.Username, u.Email)
		newHash, err := getAndHashPassword(*password)
		if err != nil {
			log.Fatalf("Gagal memproses password: %v", err)
		}
		if err := db.UpdateUserPassword(u.ID, newHash); err != nil {
			log.Fatalf("Gagal mengubah password: %v", err)
		}
	}

	fmt.Println("✓ Password berhasil diubah.")
}

// getAndHashPassword meminta password secara interaktif jika belum diisi,
// kemudian menghash dengan bcrypt.
func getAndHashPassword(rawPassword string) (string, error) {
	if rawPassword == "" {
		rawPassword = promptPassword()
	}
	if strings.TrimSpace(rawPassword) == "" {
		return "", fmt.Errorf("password tidak boleh kosong")
	}
	if len(rawPassword) < 8 {
		return "", fmt.Errorf("password minimal 8 karakter")
	}
	return auth.HashPassword(rawPassword)
}

// promptPassword meminta input password dari terminal tanpa menampilkan karakter.
func promptPassword() string {
	// Coba gunakan terminal raw mode (menyembunyikan input)
	if term.IsTerminal(int(syscall.Stdin)) {
		fmt.Print("Password baru: ")
		b, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err == nil {
			pw1 := string(b)

			fmt.Print("Konfirmasi password: ")
			b2, err2 := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err2 != nil {
				log.Fatalf("Gagal membaca konfirmasi password: %v", err2)
			}
			pw2 := string(b2)
			if pw1 != pw2 {
				fmt.Fprintln(os.Stderr, "Error: password dan konfirmasi tidak cocok")
				os.Exit(1)
			}
			return pw1
		}
	}

	// Fallback: baca dari stdin biasa (password terlihat)
	fmt.Print("Password baru (warning: teks terlihat): ")
	reader := bufio.NewReader(os.Stdin)
	pw, _ := reader.ReadString('\n')
	return strings.TrimSpace(pw)
}
