-- === Utility Functions ===

-- Logs error messages to a separate log file
function logError(message)
    local logFile = io.open("ReplayData/error_log.txt", "a")
    if logFile then
        logFile:write(os.date("[%Y-%m-%d %H:%M:%S] ") .. message .. "\n")
        logFile:close()
    end
end

-- Saves valid string to file
function saveToDisk(path, content)
    if type(content) ~= 'string' then
        logError("Attempted to save non-string content to: " .. path)
        return false
    end
    if #content < 1000 then
        logError("Skipped small result (under 1000 bytes) at path: " .. path)
        return false
    end

    local file = io.open(path, 'a')
    if not file then
        logError("Failed to open file: " .. path)
        return false
    end

    file:write(content)
    file:close()
    return true
end

-- Optional MD5 hashing for deduplication
function generateMD5(str)
    if md5sum then
        return md5sum(str)
    else
        return str:sub(1, 1000) -- fallback: crude uniqueness check
    end
end

-- === Main Script ===

local processName = 'Polaris-Win64-Shipping'
local sessionID = os.time()
local baseDir = "ReplayData"
local outputDir = string.format("%s/%d", baseDir, sessionID)

-- Create main and session directories
os.execute('mkdir "' .. baseDir .. '"')
os.execute('mkdir "' .. outputDir .. '"')

-- Attach to the process
local targetApp = openProcess(processName)
local seenHashes = {}

for scanCycle = 1, 101 do
    print(string.format("[*] Starting scan cycle %d...", scanCycle))
    pause()

    local scanner = createMemScan(targetApp)
    scanner.firstScan(
        soExactValue, vtString, nil,
        '{"replayDetailList":', '', 
        0, 0xffffffffffffffff, '', 
        fsmNotAligned, '', false, false, false, true
    )
    scanner.waitTillDone()

    local found = createFoundList(scanner)
    found.initialize()

    local total = found.getCount()
    print(string.format("[*] Found %d entries", total))

    for idx = 0, total - 1 do
        local addr = found.getAddress(idx)
        local data = readString(addr, 100000)

        local hash = generateMD5(data or "")
        if not seenHashes[hash] then
            seenHashes[hash] = true
            local fileName = string.format("%s/%d_%d.json", outputDir, sessionID, idx)
            if saveToDisk(fileName, data) then
                print(string.format("[+] Saved: %s", fileName))
            else
                print(string.format("[!] Failed to save: %s", fileName))
            end
        else
            print("[~] Duplicate result skipped.")
        end
    end

    unpause()
    print("[*] Scan cycle complete. Waiting 2 minutes...\n")
    sleep(120000)
end
