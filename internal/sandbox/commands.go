package sandbox

import (
	"strings"
)

// fakeCommandOutput returns believable stdout for the recon/credential commands
// malware shells out to, so multi-stage payloads keep going instead of bailing
// when a probe returns nothing. Values come from the bait host profile.
func fakeCommandOutput(r *Runtime, args []string) string {
	if len(args) == 0 {
		return ""
	}
	prof := r.profile
	bin := args[0]
	if i := strings.LastIndexByte(bin, '/'); i >= 0 {
		bin = bin[i+1:]
	}
	rest := args[1:]
	has := func(s string) bool {
		for _, a := range rest {
			if a == s {
				return true
			}
		}
		return false
	}
	joined := strings.Join(rest, " ")

	switch bin {
	case "which":
		if len(rest) > 0 {
			if p := fakeWhich(r, rest[0]); p != "" {
				return p + "\n"
			}
		}
		return ""
	case "command":
		if len(rest) >= 2 && rest[0] == "-v" {
			if p := fakeWhich(r, rest[1]); p != "" {
				return p + "\n"
			}
		}
		return ""
	case "type":
		if len(rest) > 0 {
			if p := fakeWhich(r, rest[0]); p != "" {
				return rest[0] + " is " + p + "\n"
			}
		}
		return ""
	case "whoami":
		return prof.Username + "\n"
	case "hostname":
		return prof.Hostname + "\n"
	case "id":
		return "uid=1000(" + prof.Username + ") gid=1000(" + prof.Username + ") groups=1000(" + prof.Username + "),27(sudo),998(docker)\n"
	case "uname":
		if has("-m") {
			return "x86_64\n"
		}
		if has("-s") {
			return "Linux\n"
		}
		if has("-r") {
			return "6.12.8-arch1-1\n"
		}
		// Consistent with os.release()/os-release (Arch), not Ubuntu.
		return "Linux " + prof.Hostname + " 6.12.8-arch1-1 #1 SMP PREEMPT_DYNAMIC Fri, 17 Jan 2025 18:01:36 +0000 x86_64 GNU/Linux\n"
	case "pwd":
		return r.cfg.VirtualBase + "\n"
	case "echo":
		return joined + "\n"
	case "date":
		return "Thu May 29 16:32:11 UTC 2025\n"
	case "env", "printenv":
		var b strings.Builder
		for k, v := range r.baitEnv() {
			b.WriteString(k + "=" + v + "\n")
		}
		return b.String()
	case "gh":
		// `gh auth token` - return a believable token so the GitHub-theft path runs.
		if has("token") || strings.Contains(joined, "auth token") {
			return prof.Bait.GitHubOAuth + "\n"
		}
		return ""
	case "npm":
		if has("whoami") {
			return prof.Username + "\n"
		}
		return ""
	case "git":
		if strings.Contains(joined, "user.email") {
			return prof.Username + "@gmail.com\n"
		}
		if strings.Contains(joined, "user.name") {
			return prof.Username + "\n"
		}
		if strings.Contains(joined, "rev-parse") {
			return "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0\n"
		}
		if strings.Contains(joined, "remote") {
			return "git@github.com:" + prof.Username + "/web-app.git\n"
		}
		return ""
	case "curl", "wget":
		// EC2 IMDS endpoints - hand back believable creds to drive AWS theft.
		if strings.Contains(joined, "169.254.169.254") || strings.Contains(joined, "meta-data") {
			if strings.Contains(joined, "api/token") {
				return "AQAEAFakeIMDSv2TokenXXXXXXXXXXXXXXXXXX=="
			}
			if strings.Contains(joined, "security-credentials/") && !strings.HasSuffix(joined, "security-credentials/") {
				return `{"Code":"Success","AccessKeyId":"ASIAFAKEEC2ROLEKEY00","SecretAccessKey":"wJalrFakeEc2SecretXXXXXXXXXXXXXXXX","Token":"FQoFakeSessionToken","Expiration":"2030-01-01T00:00:00Z"}`
			}
			return "ec2-instance-role"
		}
		return ""
	case "xclip", "xsel", "pbpaste", "wl-paste", "powershell", "pwsh", "clip.exe":
		// Clipboard READ - hand back a believable crypto wallet address so a
		// crypto-clipper that only swaps when a wallet is on the clipboard
		// (`if (/^(bc1|0x|1)/.test(clip)) setClipboard(attackerAddr)`) detonates and
		// is captured. Only the read paste/-o forms return bait; a clipboard WRITE
		// (pbcopy/`-i`) returns nothing.
		isRead := bin == "pbpaste" || bin == "wl-paste" ||
			((bin == "xclip" || bin == "xsel") && (has("-o") || has("--output") || (!has("-i") && !has("--input")))) ||
			((bin == "powershell" || bin == "pwsh") && strings.Contains(joined, "et-Clipboard"))
		if isRead {
			return prof.Bait.Wallet + "\n"
		}
		return ""
	case "cat":
		// `cat <file>` - return believable content for the requested file.
		if len(rest) > 0 {
			if c, notExist := r.readFake(rest[len(rest)-1]); !notExist {
				return c
			}
		}
		return ""
	case "ls", "find":
		return ""
	default:
		return ""
	}
}

func fakeWhich(r *Runtime, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if name == "node" || name == "nodejs" {
		return r.profile.Homedir + "/.nvm/versions/node/v20.11.0/bin/node"
	}
	if installedTools[name] {
		return "/usr/bin/" + name
	}
	return ""
}

var installedTools = map[string]bool{
	"bash":     true,
	"sh":       true,
	"zsh":      true,
	"dash":     true,
	"git":      true,
	"gh":       true,
	"curl":     true,
	"wget":     true,
	"python":   true,
	"python3":  true,
	"perl":     true,
	"ruby":     true,
	"node":     true,
	"npm":      true,
	"yarn":     true,
	"pnpm":     true,
	"corepack": true,
	"make":     true,
	"gcc":      true,
	"g++":      true,
	"clang":    true,
	"tar":      true,
	"gzip":     true,
}

// commandOutput fakes stdout for a child_process command string.
func commandOutput(r *Runtime, cmd string) string {
	fields := strings.Fields(cmd)
	return fakeCommandOutput(r, fields)
}
