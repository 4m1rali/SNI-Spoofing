from __future__ import annotations

FUN_FACTS: list[tuple[str, list[str]]] = [
    ("(o^▽^o)", [
        "Okay so like... Iran's firewall blocks websites",
        "that don't even EXIST yet?? Future-proof censorship!!",
        "That's actually kinda impressive ngl (>_<)",
    ]),
    ("(≧◡≦)", [
        "DPI stands for Deep Packet Inspection~",
        "But in Iran it stands for",
        "'Definitely Preventing Internet' hehehe (^_−)☆",
    ]),
    ("(^///^)", [
        "Iran blocked Instagram and Iranians responded by",
        "becoming the #1 VPN users in the WHOLE WORLD!!",
        "That's literally the most Iranian thing ever omg~",
    ]),
    ("(￣▽￣)ノ", [
        "The Iranian firewall once accidentally blocked",
        "a GOVERNMENT website for 3 whole days...",
        "and nobody noticed!! (≧∇≦)/",
    ]),
    ("(◕‿◕✿)", [
        "Iran's national intranet 'SHOMA' has been",
        "'almost ready' since 2012~ It's been loading",
        "for 12+ years... my patience has a limit!! (╯°□°）╯",
    ]),
    ("(｡◕‿◕｡)", [
        "The firewall blocks SO many IPs that Iranian",
        "sysadmins use VPNs just to do their own jobs~",
        "The irony is DELICIOUS hehehe (≧▽≦)",
    ]),
    ("(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧", [
        "Cloudflare hosts like 20% of the internet~",
        "Iran blocked ALL of Cloudflare's IPs!!",
        "That's not a firewall, that's a wrecking ball!! (╥_╥)",
    ]),
    ("(^_^;)", [
        "Iran blocks Telegram officially buuuut~",
        "government officials coordinate ON Telegram...",
        "I have no words. Zero. None. (¬_¬)",
    ]),
    ("(＾▽＾)", [
        "Every time a new bypass tool drops in Iran~",
        "10 MILLION people download it before lunch!!",
        "Iranians speedrun internet freedom fr fr (≧◡≦)",
    ]),
    ("(✿◠‿◠)", [
        "The SNI field was designed for virtual hosting~",
        "Iran's firewall uses it as a blacklist lookup!!",
        "Turning web standards into censorship tools... creative!! (¬‿¬)",
    ]),
    ("(o˘◡˘o)", [
        "Iran's internet speed is among the slowest globally~",
        "The firewall probably uses 40% of the bandwidth",
        "just inspecting packets!! Inspecting MY packets!! (╯°□°）╯",
    ]),
    ("(≧ω≦)", [
        "The wrong_seq trick goes like this~",
        "We send a fake hello with a broken sequence number!",
        "DPI: 'looks fine!'  Server: 'what?' *discards*",
        "Everyone wins!! Except the firewall hehehe (^_−)☆",
    ]),
    ("(｡•̀ᴗ-)✧", [
        "Iran's filter list has more entries",
        "than most countries have LAWS~",
        "That's not a blocklist, that's a lifestyle!! (≧∇≦)",
    ]),
    ("(◑‿◐)", [
        "The firewall has more false positives",
        "than a broken smoke detector in a bakery~",
        "Blocking bread recipes since 2009!! (╥_╥)",
    ]),
    ("(^◡^)", [
        "Iran has a 'Committee Charged with Determining",
        "Offensive Content'~ That's a real government job!!",
        "Imagine that on your resume... (¬_¬)",
    ]),
    ("(✧ω✧)", [
        "During protests Iran shuts down the internet~",
        "The whole internet!! For the whole country!!",
        "That's not a firewall, that's a light switch!! (╯°□°）╯",
    ]),
    ("(◕ᴗ◕✿)", [
        "Iran blocked WhatsApp, Telegram, Instagram, Twitter~",
        "YouTube, Facebook, Snapchat, TikTok, and more!!",
        "At this point just block the internet and be honest!! (≧∇≦)",
    ]),
    ("(｡♥‿♥｡)", [
        "TLS 1.3 encrypts the SNI field with ESNI/ECH~",
        "Iran's response? Block ALL encrypted SNI traffic!!",
        "If you can't read it, ban it~ Big brain move!! (¬‿¬)",
    ]),
    ("(≧◡≦) ♡", [
        "NexNull bypasses DPI by lying to it politely~",
        "We don't hack anything, we just... misdirect!!",
        "It's not lying, it's creative packet engineering!! (^_−)☆",
    ]),
    ("(ﾉ^ヮ^)ﾉ", [
        "Iran's firewall engineers probably use VPNs",
        "to test if their own firewall works~",
        "The ouroboros of censorship!! (≧▽≦)",
    ]),
    ("(◠‿◠✿)", [
        "A TCP sequence number is supposed to be random~",
        "We make it EXTRA random — so random it's wrong!!",
        "The server ignores it, DPI falls for it~ Perfect!! (✿◠‿◠)",
    ]),
    ("(ﾉ´ヮ`)ﾉ*: ･ﾟ", [
        "patterniha built the original SNI-Spoofing engine~",
        "A genius who fights for free internet in Iran!!",
        "We stand on the shoulders of legends (≧▽≦) ♡",
    ]),
    ("(*^▽^*)", [
        "Iran once slowed internet to 56kbps during elections~",
        "56kbps!! That's dial-up speed!! In 2024!!",
        "My grandma's modem is faster than that!! (╯°□°）╯",
    ]),
    ("(ﾉ◕ヮ◕)ﾉ", [
        "The Iranian government calls VPNs 'illegal'~",
        "But sells licensed VPNs through state companies!!",
        "Monopoly on censorship bypass... respect the hustle!! (¬‿¬)",
    ]),
    ("(✪ω✪)", [
        "Iran's firewall inspects TLS handshakes~",
        "So we send a FAKE handshake first!!",
        "It's like showing a fake ID to a bouncer (^_−)☆",
    ]),
    ("(づ｡◕‿‿◕｡)づ", [
        "Every packet we send goes through WinDivert~",
        "WinDivert is like a tiny ninja intercepting packets!!",
        "Ninja packets!! That's literally what we do!! (≧▽≦)",
    ]),
    ("(＾• ω •＾)", [
        "Iran blocked GitHub for a while~",
        "GitHub!! Where developers live!!",
        "Blocking GitHub is a crime against humanity!! (╥_╥)",
    ]),
    ("(◍•ᴗ•◍)❤", [
        "The fake SNI we send is a real whitelisted domain~",
        "The DPI sees it and goes 'oh that's fine!'",
        "Then we swap to real traffic~ Sneaky sneaky!! (^_−)☆",
    ]),
    ("(｡>﹏<｡)", [
        "Iran blocked Wikipedia in 2017~",
        "WIKIPEDIA!! The free encyclopedia!!",
        "They blocked KNOWLEDGE itself!! (╯°□°）╯",
    ]),
    ("(ﾉ≧∀≦)ﾉ", [
        "The Iranian firewall is called FATA~",
        "Which stands for Cyber Police in Persian~",
        "Cyber Police sounds like a 90s cartoon villain!! (≧▽≦)",
    ]),
    ("(◕‿◕)", [
        "Iran has over 85 million people~",
        "And roughly 70 million of them use VPNs~",
        "That's not a statistic, that's a revolution!! (✿◠‿◠)",
    ]),
    ("(＾ω＾)", [
        "The firewall blocks so many ports~",
        "that some Iranian devs can't even use SSH!!",
        "Can't SSH into your own server... peak dystopia!! (╥_╥)",
    ]),
    ("(｡•́‿•̀｡)", [
        "Iran's internet is so filtered~",
        "that searching 'how to search the internet' is blocked~",
        "Okay I made that up but it FEELS true!! (^_^;)",
    ]),
    ("(≧◡≦)✨", [
        "WinDivert operates at the kernel level~",
        "It intercepts packets BEFORE they leave your PC!!",
        "We're basically packet ninjas with admin rights!! (✧ω✧)",
    ]),
    ("(ﾉ´з`)ﾉ", [
        "Iran blocked LinkedIn~",
        "LinkedIn!! The most boring social network!!",
        "Even job hunting is censored... (¬_¬)",
    ]),
    ("(*≧ω≦*)", [
        "The TCP three-way handshake is SYN, SYN-ACK, ACK~",
        "We intercept the ACK and inject a fake PSH after it!!",
        "We're basically doing TCP surgery!! (≧▽≦)",
    ]),
    ("(◠‿◠)", [
        "Iran's firewall uses Deep Packet Inspection~",
        "DPI reads your packets like a nosy neighbor~",
        "So we send it a fake letter first!! (^_−)☆",
    ]),
    ("(ﾉ◕ヮ◕)ﾉ♪", [
        "Iranians invented chess, algebra, and poetry~",
        "Now they're inventing new ways to bypass firewalls~",
        "The intellectual tradition continues!! (≧◡≦) ♡",
    ]),
    ("(✿ヘᴥヘ)", [
        "The firewall blocks based on SNI~",
        "SNI is like the 'To:' field on an envelope~",
        "We write a fake address on the envelope!! (^_−)☆",
    ]),
    ("(｡◕‿◕｡)♡", [
        "Iran's internet shutdown during Mahsa Amini protests~",
        "lasted weeks and cost billions in economic damage~",
        "Censorship is expensive!! Who knew!! (╯°□°）╯",
    ]),
    ("(≧ω≦)✧", [
        "The wrong_seq number we use is calculated as~",
        "syn_seq + 1 - len(fake_payload)~",
        "Math class finally paid off!! (≧▽≦)",
    ]),
    ("(ﾉ^o^)ﾉ", [
        "Iran blocked Skype, Viber, and Line~",
        "Then blocked WhatsApp, then Telegram~",
        "At this point just use carrier pigeons!! (╥_╥)",
    ]),
    ("(◕ᴗ◕)", [
        "The Iranian government has 'approved' apps~",
        "Like Soroush and iGap~ Made in Iran!!",
        "Spoiler: they're monitored by the government!! (¬_¬)",
    ]),
    ("(*^‿^*)", [
        "NexNull's fake ClientHello is 517 bytes~",
        "Perfectly crafted to look like real TLS 1.3!!",
        "We're basically TLS cosplayers!! (≧◡≦)",
    ]),
    ("(ﾉ≧ڡ≦)ﾉ", [
        "Iran's firewall has a whitelist of 'approved' sites~",
        "The list includes government sites and state media~",
        "Shocking. Truly shocking. (¬‿¬)",
    ]),
    ("(◍•ᴗ•◍)", [
        "Every connection through NexNull gets a fresh~",
        "random 32-byte session ID, random, and key_share!!",
        "We're so random the DPI can't fingerprint us!! (✧ω✧)",
    ]),
    ("(ﾉ´ヮ`)ﾉ", [
        "Iran blocked the Tor network~",
        "So people use bridges~ Then Iran blocked bridges~",
        "It's whack-a-mole but with human rights!! (╯°□°）╯",
    ]),
    ("(≧◡≦)~♡", [
        "The padding extension in our fake ClientHello~",
        "normalizes the packet to exactly 517 bytes!!",
        "Size consistency = harder to fingerprint~ Smart!! (^_−)☆",
    ]),
    ("(｡♡‿♡｡)", [
        "Iran's internet filter was built with help from~",
        "companies that later got sanctioned for it~",
        "Karma is a DPI system!! (≧∇≦)",
    ]),
    ("(ﾉ◕ヮ◕)ﾉ~", [
        "asyncio lets us handle thousands of connections~",
        "with just ONE thread!! No blocking!!",
        "Python is secretly a speed demon!! (≧▽≦)",
    ]),
    ("(✿◕‿◕)", [
        "Iran's firewall checks the SNI in TLS ClientHello~",
        "So we send a FAKE ClientHello with a fake SNI~",
        "Then the real connection happens after~ Genius!! (^_−)☆",
    ]),
    ("(ﾉ^ヮ^)ﾉ✨", [
        "TCP keepalive pings every 11 seconds~",
        "So idle connections don't get dropped!!",
        "We care about our connections~ Unlike the firewall!! (≧◡≦)",
    ]),
    ("(◠‿◠✿)~", [
        "Iran's internet is so slow during peak hours~",
        "that loading a webpage feels like archaeology~",
        "Digging through layers of throttling!! (╥_╥)",
    ]),
    ("(*≧▽≦*)", [
        "The ThreadPoolExecutor handles fake-send tasks~",
        "32 workers ready to inject fake packets!!",
        "We have an ARMY of packet ninjas!! (≧▽≦)",
    ]),
    ("(｡>‿‿<｡)", [
        "Iran's firewall was inspired by China's Great Firewall~",
        "But Iran added extra steps and extra blocks~",
        "Overachievers!! (¬_¬)",
    ]),
    ("(ﾉ´▽`)ﾉ", [
        "Every time Iran blocks a new app~",
        "Iranian developers build a clone of it~",
        "Censorship is the mother of invention!! (≧◡≦)",
    ]),
    ("(◕‿◕✿)~", [
        "The bypass handshake timeout is configurable~",
        "Default is 2 seconds~ If it takes longer~",
        "The firewall is being extra suspicious today!! (^_^;)",
    ]),
    ("(ﾉ≧∀≦)ﾉ✨", [
        "Iran's internet has 'quality of service' rules~",
        "Domestic traffic: fast~ International: throttled~",
        "It's not a bug, it's a feature!! (¬‿¬)",
    ]),
    ("(｡•̀ᴗ•́｡)✧", [
        "NexNull logs the real SNI from your client~",
        "So you can see exactly what sites you're accessing!!",
        "Transparency!! Unlike the firewall!! (≧▽≦)",
    ]),
    ("(ﾉ◕ヮ◕)ﾉ❤", [
        "Iran blocked Google Play Store~",
        "So Iranians use APK sites and third-party stores~",
        "Where there are definitely no viruses~ Definitely!! (^_^;)",
    ]),
    ("(≧◡≦)♪", [
        "The stats in the title bar update every 2 seconds~",
        "Total requests, active connections, bytes transferred!!",
        "We're basically a mini network monitor!! (✧ω✧)",
    ]),
    ("(◍•ᴗ•◍)✨", [
        "Iran's firewall has been active since the early 2000s~",
        "Over 20 years of blocking the internet!!",
        "That's older than most of my favorite anime!! (╥_╥)",
    ]),
]
