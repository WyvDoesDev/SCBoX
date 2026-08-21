package sandbox

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
)

// This file generates the believable host identity the sandbox presents. The
// identity is RANDOMIZED once per run (seeded unpredictably) so that the
// analyzer can't be fingerprinted by constant tells: a published tool that always
// claimed to be host "valkyrie", user "alex", MAC 1c:1b:0d:7a:3e:9f, machine-id
// 9a3c…, etc. would let evasive malware detect it with a single equality check.
// Every value is drawn from pools of real, mundane, VM-string-free consumer data,
// so each run still looks like an ordinary developer workstation - just a
// DIFFERENT one each time.

// hostProfile is the believable identity presented to the sample. Values are
// deliberately mundane and VM-string-free (no "sandbox", "vbox", "qemu", ...).
type hostProfile struct {
	Hostname string
	Username string
	Homedir  string
	Arch     string
	CPU      cpuProfile
	TotalMem int64 // bytes
	MAC      string
	IP       string
	Gateway  string // LAN router, for resolv.conf / DNS

	MachineID   string // /etc/machine-id - a stable unique host id (classic tell)
	ProductUUID string // /sys/class/dmi/id/product_uuid
	SysVendor   string
	ProductName string
	BoardName   string
	BiosVendor  string

	PID  int // the faked node process id
	PPID int // its parent (a shell, as under a real `npm install`)

	Bait baitCreds
}

// cpuProfile carries the matched set of /proc/cpuinfo fields for one real
// consumer CPU, so the model name, vendor, family and flags stay consistent.
type cpuProfile struct {
	Model    string
	Threads  int // logical processors (siblings)
	Cores    int // physical cores
	VendorID string
	Family   int
	ModelNum int
	MHz      string
	CacheKB  int
	Bogo     string
	Flags    string
}

// baitCreds are shape-valid but randomized decoy secrets. The shapes still match
// the verdict's credential regexes (AKIA…, ghp_…, npm_…, sk_live_…), so an exfil
// attempt is captured - but the concrete values differ every run, so they can't
// be recognized as "the SCBoX bait".
type baitCreds struct {
	NPMToken    string
	AWSKeyID    string
	AWSSecret   string
	GitHubToken string
	GitHubOAuth string
	StripeKey   string
	JWTSecret   string
	DBPass      string
	DockerAuth  string // base64(user:token)
	Wallet      string // bait BTC address (served on clipboard reads to trip clippers)
	WalletKey   string // bait wallet private key (hex, served in .env / env)
	Mnemonic    string // bait BIP39 seed phrase (served in .env / env)
}

const profileSeedEnv = "SCBOX_PROFILE_SEED"

var (
	profileOnce sync.Once
	profileVal  hostProfile
)

// profileSeed returns the per-run seed. It is generated unpredictably on first
// use and propagated through the environment so a spawned worker subprocess
// derives the EXACT same identity - the parent computes DefaultVirtualRoot()
// (and thus the profile) before forking the jailed child, so the env var is
// already set and inherited. This keeps os.homedir() consistent with the project
// path the parent embedded, across the process boundary.
func profileSeed() int64 {
	if s := os.Getenv(profileSeedEnv); s != "" {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			return v
		}
	}
	var b [8]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		// crypto/rand should never fail; fall back to a process-unique-ish value.
		binary.LittleEndian.PutUint64(b[:], uint64(os.Getpid())*2654435761)
	}
	seed := int64(binary.LittleEndian.Uint64(b[:]))
	_ = os.Setenv(profileSeedEnv, strconv.FormatInt(seed, 10))
	return seed
}

// defaultProfile returns the run's randomized identity, built once and cached so
// every Runtime in this process (including the parallel explore workers) presents
// the same consistent host.
func defaultProfile() hostProfile {
	profileOnce.Do(func() {
		profileVal = buildProfile(mrand.New(mrand.NewSource(profileSeed())))
	})
	return profileVal
}

// --- value pools (all real, mundane, VM-free) ---

var (
	usernamePool = []string{
		"alex", "sam", "chris", "jordan", "taylor", "jamie", "morgan", "casey",
		"riley", "quinn", "drew", "jesse", "cameron", "devin", "dan", "mike",
		"sarah", "emma", "noah", "liam", "ava", "leo", "max", "nina",
	}
	hostnamePool = []string{
		"valkyrie", "nebula", "orion", "raptor", "phoenix", "titan", "vega",
		"atlas", "cosmos", "hyperion", "zenith", "onyx", "cobalt", "helios",
		"draco", "lyra", "nova", "quartz", "kraken", "sentinel",
	}
	// Real consumer NIC OUIs (ASUS, Intel, Realtek, Dell, MSI, Gigabyte). None are
	// VM prefixes (VMware 00:05:69/00:0c:29/00:50:56, VirtualBox 08:00:27,
	// QEMU/KVM 52:54:00, Xen 00:16:3e, Hyper-V 00:15:5d are all excluded).
	macOUIPool = []string{
		"1c:1b:0d", "2c:fd:a1", "d8:5e:d3", // ASUSTek
		"3c:fd:fe", "a4:bb:6d", "94:c6:91", // Intel
		"00:e0:4c", "52:74:f2", // Realtek (52:74:f2 is Realtek, not 52:54:00)
		"f8:bc:12", "00:14:22", // Dell
		"00:d8:61", "30:9c:23", // MSI
		"94:de:80", "b4:2e:99", // Gigabyte
	}
	// (sys_vendor, product_name, board_name, bios_vendor) - consistent consumer
	// desktop/laptop units.
	dmiPool = [][4]string{
		{"ASUSTeK COMPUTER INC.", "System Product Name", "PRIME B550-PLUS", "American Megatrends Inc."},
		{"ASUSTeK COMPUTER INC.", "System Product Name", "TUF GAMING X570-PLUS", "American Megatrends Inc."},
		{"Micro-Star International Co., Ltd.", "MS-7C56", "B450M PRO-VDH MAX (MS-7C56)", "American Megatrends Inc."},
		{"Gigabyte Technology Co., Ltd.", "B550 AORUS ELITE", "B550 AORUS ELITE", "American Megatrends Inc."},
		{"Dell Inc.", "XPS 15 9520", "0R6JFH", "Dell Inc."},
		{"LENOVO", "20XW004YUS", "20XW004YUS", "LENOVO"},
	}
	amdFlags   = "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl tsc_reliable nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand"
	intelFlags = "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx est tm2 ssse3 sdbg fma cx16 xtpr pdcm sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch"

	cpuPool = []cpuProfile{
		{Model: "AMD Ryzen 5 5600X 6-Core Processor", Threads: 12, Cores: 6, VendorID: "AuthenticAMD", Family: 25, ModelNum: 33, MHz: "3700.000", CacheKB: 512, Bogo: "7400.00", Flags: amdFlags},
		{Model: "AMD Ryzen 7 5800X 8-Core Processor", Threads: 16, Cores: 8, VendorID: "AuthenticAMD", Family: 25, ModelNum: 33, MHz: "3800.000", CacheKB: 512, Bogo: "7600.00", Flags: amdFlags},
		{Model: "AMD Ryzen 9 5900X 12-Core Processor", Threads: 24, Cores: 12, VendorID: "AuthenticAMD", Family: 25, ModelNum: 33, MHz: "3700.000", CacheKB: 512, Bogo: "7400.00", Flags: amdFlags},
		{Model: "Intel(R) Core(TM) i5-10600K CPU @ 4.10GHz", Threads: 12, Cores: 6, VendorID: "GenuineIntel", Family: 6, ModelNum: 165, MHz: "4100.000", CacheKB: 12288, Bogo: "8200.00", Flags: intelFlags},
		{Model: "Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz", Threads: 16, Cores: 8, VendorID: "GenuineIntel", Family: 6, ModelNum: 165, MHz: "3800.000", CacheKB: 16384, Bogo: "7600.00", Flags: intelFlags},
		{Model: "Intel(R) Core(TM) i9-12900K", Threads: 24, Cores: 16, VendorID: "GenuineIntel", Family: 6, ModelNum: 151, MHz: "3200.000", CacheKB: 30720, Bogo: "6374.00", Flags: intelFlags},
	}
	memByThreads = map[int]int64{12: 16, 16: 32, 24: 64} // logical CPUs → GiB, a believable pairing
)

// buildProfile assembles one consistent random identity from rng.
func buildProfile(rng *mrand.Rand) hostProfile {
	pick := func(s []string) string { return s[rng.Intn(len(s))] }

	user := pick(usernamePool)
	cpu := cpuPool[rng.Intn(len(cpuPool))]
	memGiB := memByThreads[cpu.Threads]
	if memGiB == 0 {
		memGiB = 32
	}
	dmi := dmiPool[rng.Intn(len(dmiPool))]

	return hostProfile{
		Hostname:    pick(hostnamePool),
		Username:    user,
		Homedir:     "/home/" + user,
		Arch:        "x64",
		CPU:         cpu,
		TotalMem:    memGiB << 30,
		MAC:         randMAC(rng),
		IP:          fmt.Sprintf("192.168.%d.%d", 1+rng.Intn(2), 20+rng.Intn(200)),
		Gateway:     "192.168.1.1",
		MachineID:   randHex(rng, 32),
		ProductUUID: randUUID(rng),
		SysVendor:   dmi[0],
		ProductName: dmi[1],
		BoardName:   dmi[2],
		BiosVendor:  dmi[3],
		PID:         2000 + rng.Intn(60000),
		PPID:        1000 + rng.Intn(8000),
		Bait: baitCreds{
			NPMToken:    "npm_" + randAlnum(rng, 36),
			AWSKeyID:    "AKIA" + randUpperNum(rng, 16),
			AWSSecret:   randB64Secret(rng, 40),
			GitHubToken: "ghp_" + randAlnum(rng, 36),
			GitHubOAuth: "gho_" + randAlnum(rng, 36),
			StripeKey:   "sk_live_" + randAlnum(rng, 24),
			JWTSecret:   randAlnum(rng, 32),
			DBPass:      randAlnum(rng, 16),
			DockerAuth:  randAlnum(rng, 32), // stands in for base64(user:token)
			// base58 (no 0 O I l), the shape a real BTC address takes.
			Wallet:   "1" + randFrom(rng, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", 33),
			WalletKey: randHex(rng, 64), // 32-byte private key
			Mnemonic:  randMnemonic(rng),
		},
	}
}

// bip39Sample is a small slice of the BIP39 wordlist - enough to render a
// believable 12-word seed phrase as bait (the value is what matters for taint, not
// a valid checksum).
var bip39Sample = []string{
	"abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
	"access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire",
	"across", "action", "actor", "actual", "adapt", "add", "addict", "address",
	"adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford",
	"afraid", "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle",
	"alarm", "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost",
	"alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
}

// randMnemonic renders a believable 12-word seed phrase from bip39Sample.
func randMnemonic(rng *mrand.Rand) string {
	words := make([]string, 12)
	for i := range words {
		words[i] = bip39Sample[rng.Intn(len(bip39Sample))]
	}
	return strings.Join(words, " ")
}

// --- random primitives (believability only; unpredictability comes from seed) ---

func randFrom(rng *mrand.Rand, alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(b)
}

func randHex(rng *mrand.Rand, n int) string { return randFrom(rng, "0123456789abcdef", n) }
func randAlnum(rng *mrand.Rand, n int) string {
	return randFrom(rng, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", n)
}
func randUpperNum(rng *mrand.Rand, n int) string {
	return randFrom(rng, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", n)
}
func randB64Secret(rng *mrand.Rand, n int) string {
	return randFrom(rng, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", n)
}

// randUUID renders a random RFC-4122 v4 UUID string.
func randUUID(rng *mrand.Rand) string {
	var b [16]byte
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 1
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// randMAC builds a MAC from a real consumer OUI plus three random octets.
func randMAC(rng *mrand.Rand) string {
	oui := macOUIPool[rng.Intn(len(macOUIPool))]
	return fmt.Sprintf("%s:%02x:%02x:%02x", oui, rng.Intn(256), rng.Intn(256), rng.Intn(256))
}
