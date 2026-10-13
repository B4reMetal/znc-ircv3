// Full-text index behind chathistory's SEARCH (soju.im/search).
//
// SQLite database, one per ZNC user, next to that user's history
// directories (<moddata>/<user>/.search.db). The day files stay the source
// of truth; the index holds, per PRIVMSG/NOTICE, the network and target
// directory names, time, lower-cased sender nick, msgid, the byte range of
// the line inside its day file, and the text with formatting codes stripped.
// Text is indexed by an FTS5 trigram table, so `text=` keeps its substring
// semantics (case-insensitive, no word boundaries) and short queries (under
// three characters) fall back to a plain scan of the text column.
//
// Row ids are derived from the message time (seconds * 64 + n), so the FTS
// table can hand back matches newest-first (ORDER BY rowid DESC LIMIT n)
// without sorting every hit, and after=/before= become rowid ranges. Two
// extra FTS columns hold short hash tokens for the network/target (`loc`)
// and the sender (`who`), so in= and from= narrow the search inside FTS;
// equality filters in SQL remove hash collisions.
//
// The `days` table records the size of every indexed day file. The sync job
// in chathistory compares it with the files on disk and re-indexes a day
// whose size changed (the importer rewrites files; so does redaction).
//
// Schema changes: bump kSchemaVersion and append a Migration whose SQL
// takes a database from the previous version to the new one. Migrations run
// in order inside one transaction each, at Open(); a database newer than
// this code is refused. To change the FTS table itself, drop and recreate it
// in the migration and finish with INSERT INTO fts(fts) VALUES('rebuild'),
// or empty `days` so the sync job re-reads every file.
#pragma once
#include <znc/ZNCString.h>

#include <sqlite3.h>

#include <chrono>
#include <cstdio>
#include <ctime>
#include <map>
#include <vector>

namespace ircv3 {

struct IndexRow {
    CString sNetwork, sTarget, sDay, sTime, sNick, sMsgId;
    long long lOff = 0, lLen = 0;
    CString sText;  // formatting stripped
};

// Seconds since the epoch of a server-time string (0 if unparsable).
inline long long TimeSeconds(const CString& s) {
    struct tm tm = {};
    int ms = 0;
    if (sscanf(s.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d.%3dZ", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min,
               &tm.tm_sec, &ms) < 6)
        return 0;
    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    return (long long)timegm(&tm);
}

const long long kIdsPerSecond = 64;
inline long long IdBase(long long lSeconds) { return lSeconds * kIdsPerSecond; }

// Six base-36 characters of an FNV-1a hash of the lower-cased string: the
// token FTS matches on for in= / from=.
inline CString HashToken(const CString& s) {
    unsigned int h = 2166136261u;
    for (unsigned char c : s.AsLower()) h = (h ^ c) * 16777619u;
    unsigned long long v = h % 2176782336ull;  // 36^6
    char buf[7] = "000000";
    for (int i = 5; i >= 0; i--) { buf[i] = "0123456789abcdefghijklmnopqrstuvwxyz"[v % 36]; v /= 36; }
    return buf;
}
inline CString LocToken(const CString& sNet, const CString& sTarget) {
    return HashToken(sNet) + "/" + (sTarget.empty() ? CString() : HashToken(sTarget));
}

struct IndexHit {
    CString sTarget, sDay, sTime, sMsgId;
    long long lOff = 0, lLen = 0;
};

struct SearchSpec {
    CString sNetwork, sTarget, sNick, sAfter, sBefore, sText;  // directory names; nick lower-case
    size_t uLimit = 100;
    bool bForward = false;  // oldest first (after= given)
    long lMaxMillis = 2000;
};

// mIRC-style formatting: bold, italic, underline, strikethrough, monospace,
// reverse, reset and colour codes with their digits.
inline CString StripFormatting(const CString& s) {
    CString out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); i++) {
        unsigned char c = s[i];
        if (c == 0x03) {
            size_t j = i + 1, n = 0;
            while (j < s.size() && n < 2 && isdigit((unsigned char)s[j])) { j++; n++; }
            if (n && j + 1 < s.size() && s[j] == ',' && isdigit((unsigned char)s[j + 1])) {
                size_t k = j + 1, m = 0;
                while (k < s.size() && m < 2 && isdigit((unsigned char)s[k])) { k++; m++; }
                j = k;
            }
            i = j - 1;
            continue;
        }
        if (c == 0x02 || c == 0x1d || c == 0x1f || c == 0x1e || c == 0x11 || c == 0x16 || c == 0x0f) continue;
        out += (char)c;
    }
    return out;
}

inline size_t Utf8Length(const CString& s) {
    size_t n = 0;
    for (unsigned char c : s)
        if ((c & 0xC0) != 0x80) n++;
    return n;
}

class SearchIndex {
  public:
    static constexpr int kSchemaVersion = 2;

    struct Migration {
        int iTo;
        const char* sSql;
        bool bRecreate = false;  // start from an empty file instead (instant; the sync job rebuilds)
    };
    static const std::vector<Migration>& Migrations() {
        static const std::vector<Migration> v = {
            {1, R"SQL(
CREATE TABLE msg(
    id      INTEGER PRIMARY KEY,
    network TEXT NOT NULL,
    target  TEXT NOT NULL,
    day     TEXT NOT NULL,
    time    TEXT NOT NULL,
    nick    TEXT NOT NULL,
    msgid   TEXT NOT NULL,
    off     INTEGER NOT NULL,
    len     INTEGER NOT NULL,
    text    TEXT NOT NULL);
CREATE INDEX msg_target_time ON msg(network, target, time);
CREATE INDEX msg_nick_time ON msg(network, nick, time);
CREATE UNIQUE INDEX msg_msgid ON msg(network, target, msgid) WHERE msgid != '';
CREATE VIRTUAL TABLE fts USING fts5(text, content='msg', content_rowid='id', tokenize='trigram', columnsize=0);
CREATE TRIGGER msg_ai AFTER INSERT ON msg BEGIN
    INSERT INTO fts(rowid, text) VALUES (new.id, new.text);
END;
CREATE TRIGGER msg_ad AFTER DELETE ON msg BEGIN
    INSERT INTO fts(fts, rowid, text) VALUES ('delete', old.id, old.text);
END;
CREATE TABLE days(
    network TEXT NOT NULL,
    target  TEXT NOT NULL,
    day     TEXT NOT NULL,
    bytes   INTEGER NOT NULL,
    PRIMARY KEY (network, target, day)) WITHOUT ROWID;
)SQL"},
            // 2: time-derived ids, loc/who tokens. Everything is rebuilt
            // from the day files, so an old database is simply replaced.
            {2, R"SQL(
DROP TRIGGER IF EXISTS msg_ai;
DROP TRIGGER IF EXISTS msg_ad;
DROP TABLE IF EXISTS fts;
DROP TABLE IF EXISTS msg;
DELETE FROM days;
CREATE TABLE msg(
    id      INTEGER PRIMARY KEY,
    network TEXT NOT NULL,
    target  TEXT NOT NULL,
    day     TEXT NOT NULL,
    time    TEXT NOT NULL,
    nick    TEXT NOT NULL,
    msgid   TEXT NOT NULL,
    off     INTEGER NOT NULL,
    len     INTEGER NOT NULL,
    loc     TEXT NOT NULL,
    who     TEXT NOT NULL,
    text    TEXT NOT NULL);
CREATE INDEX msg_target_time ON msg(network, target, time);
CREATE INDEX msg_nick_time ON msg(network, nick, time);
CREATE UNIQUE INDEX msg_msgid ON msg(network, target, msgid) WHERE msgid != '';
CREATE VIRTUAL TABLE fts USING fts5(loc, who, text, content='msg', content_rowid='id', tokenize='trigram', columnsize=0);
CREATE TRIGGER msg_ai AFTER INSERT ON msg BEGIN
    INSERT INTO fts(rowid, loc, who, text) VALUES (new.id, new.loc, new.who, new.text);
END;
CREATE TRIGGER msg_ad AFTER DELETE ON msg BEGIN
    INSERT INTO fts(fts, rowid, loc, who, text) VALUES ('delete', old.id, old.loc, old.who, old.text);
END;
)SQL", true},
        };
        return v;
    }

    SearchIndex() = default;
    SearchIndex(const SearchIndex&) = delete;
    SearchIndex& operator=(const SearchIndex&) = delete;
    ~SearchIndex() { Close(); }

    bool IsOpen() const { return m_pDb != nullptr; }
    const CString& Path() const { return m_sPath; }

    // bRecreateOk: a pending "recreate" migration may replace the file.
    // Only one connection must ever do that (the module does it at load,
    // on the main thread, before the sync job starts); other connections
    // report the old schema as an error instead.
    bool Open(const CString& sPath, CString& sError, int iBusyMillis = 3000, bool bRecreateOk = false) {
        for (int iPass = 0; iPass < 2; iPass++) {
            Close();
            if (sqlite3_open_v2(sPath.c_str(), &m_pDb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
                sError = m_pDb ? sqlite3_errmsg(m_pDb) : "cannot open";
                Close();
                return false;
            }
            m_sPath = sPath;
            sqlite3_busy_timeout(m_pDb, iBusyMillis);
            bool bRecreate = false;
            if (!Exec("PRAGMA journal_mode=WAL") || !Exec("PRAGMA synchronous=NORMAL") || !Exec("PRAGMA temp_store=MEMORY") ||
                !Migrate(sError, bRecreate)) {
                if (sError.empty()) sError = LastError();
                Close();
                return false;
            }
            if (!bRecreate) return true;
            if (!bRecreateOk || iPass == 1) {
                sError = "index schema is outdated and must be recreated";
                Close();
                return false;
            }
            Close();
            for (const char* sSuffix : {"", "-wal", "-shm"}) ::remove((sPath + sSuffix).c_str());
        }
        return false;
    }

    void Close() {
        for (auto& kv : m_mStmts) sqlite3_finalize(kv.second);
        m_mStmts.clear();
        if (m_pDb) sqlite3_close(m_pDb);
        m_pDb = nullptr;
        m_sPath.clear();
    }

    CString LastError() const { return m_pDb ? CString(sqlite3_errmsg(m_pDb)) : CString("not open"); }

    bool Exec(const char* sSql) {
        if (!m_pDb) return false;
        char* sErr = nullptr;
        int rc = sqlite3_exec(m_pDb, sSql, nullptr, nullptr, &sErr);
        if (sErr) sqlite3_free(sErr);
        return rc == SQLITE_OK;
    }
    bool Begin() { return Exec("BEGIN IMMEDIATE"); }
    bool Commit() { return Exec("COMMIT"); }
    void Rollback() { Exec("ROLLBACK"); }

    // ---- writing ----------------------------------------------------------

    // A message already present (same network/target/msgid) is left alone.
    bool Insert(const IndexRow& r) {
        const long long lBase = IdBase(TimeSeconds(r.sTime));
        // The next free id at or after the second's base. A burst of more
        // than kIdsPerSecond lines spills into the following seconds, so
        // look further ahead on every retry.
        long long lWindow = kIdsPerSecond;
        for (int iTry = 0; iTry < 12; iTry++, lWindow *= 4) {
            long long lId = lBase;
            sqlite3_stmt* mx = Stmt("SELECT max(id) FROM msg WHERE id >= ? AND id < ?");
            if (!mx) return false;
            sqlite3_bind_int64(mx, 1, lBase); sqlite3_bind_int64(mx, 2, lBase + lWindow);
            if (sqlite3_step(mx) == SQLITE_ROW && sqlite3_column_type(mx, 0) != SQLITE_NULL) lId = sqlite3_column_int64(mx, 0) + 1;
            sqlite3_reset(mx);
            sqlite3_stmt* st = Stmt("INSERT INTO msg(id,network,target,day,time,nick,msgid,off,len,loc,who,text) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)");
            if (!st) return false;
            sqlite3_bind_int64(st, 1, lId);
            Bind(st, 2, r.sNetwork); Bind(st, 3, r.sTarget); Bind(st, 4, r.sDay); Bind(st, 5, r.sTime);
            Bind(st, 6, r.sNick); Bind(st, 7, r.sMsgId);
            sqlite3_bind_int64(st, 8, r.lOff); sqlite3_bind_int64(st, 9, r.lLen);
            Bind(st, 10, LocToken(r.sNetwork, r.sTarget)); Bind(st, 11, HashToken(r.sNick)); Bind(st, 12, r.sText);
            int rc = sqlite3_step(st);
            sqlite3_reset(st);
            if (rc == SQLITE_DONE) return true;
            if (rc != SQLITE_CONSTRAINT) return false;
            // Either the message is already indexed or another connection
            // took the id in between: tell them apart and retry the latter.
            if (!r.sMsgId.empty()) {
                sqlite3_stmt* ex = Stmt("SELECT 1 FROM msg WHERE network=? AND target=? AND msgid=?");
                if (!ex) return false;
                Bind(ex, 1, r.sNetwork); Bind(ex, 2, r.sTarget); Bind(ex, 3, r.sMsgId);
                bool bDup = sqlite3_step(ex) == SQLITE_ROW;
                sqlite3_reset(ex);
                if (bDup) return true;
            }
        }
        return false;
    }

    // The day file grew by lAdded bytes. Creates the record only when asked
    // (a file this module just created); otherwise an unknown file is left
    // for the sync job, which indexes it whole.
    bool BumpDay(const CString& sNet, const CString& sTarget, const CString& sDay, long long lAdded, bool bCreate) {
        sqlite3_stmt* st = Stmt("UPDATE days SET bytes = bytes + ? WHERE network=? AND target=? AND day=?");
        if (!st) return false;
        sqlite3_bind_int64(st, 1, lAdded); Bind(st, 2, sNet); Bind(st, 3, sTarget); Bind(st, 4, sDay);
        if (!Step(st)) return false;
        if (sqlite3_changes(m_pDb) > 0 || !bCreate) return true;
        return SetDay(sNet, sTarget, sDay, lAdded);
    }

    bool SetDay(const CString& sNet, const CString& sTarget, const CString& sDay, long long lBytes) {
        sqlite3_stmt* st = Stmt("INSERT OR REPLACE INTO days(network,target,day,bytes) VALUES(?,?,?,?)");
        if (!st) return false;
        Bind(st, 1, sNet); Bind(st, 2, sTarget); Bind(st, 3, sDay); sqlite3_bind_int64(st, 4, lBytes);
        return Step(st);
    }

    // Removes a day's messages (and its size record when bRecord).
    bool DeleteDay(const CString& sNet, const CString& sTarget, const CString& sDay, bool bRecord = true) {
        sqlite3_stmt* st = Stmt("DELETE FROM msg WHERE network=? AND target=? AND time >= ? AND time < ?");
        if (!st) return false;
        Bind(st, 1, sNet); Bind(st, 2, sTarget); Bind(st, 3, sDay); Bind(st, 4, sDay + "~");
        if (!Step(st)) return false;
        if (!bRecord) return true;
        st = Stmt("DELETE FROM days WHERE network=? AND target=? AND day=?");
        if (!st) return false;
        Bind(st, 1, sNet); Bind(st, 2, sTarget); Bind(st, 3, sDay);
        return Step(st);
    }

    // Replaces a whole day: rows re-read from the file plus its new size.
    bool ReplaceDay(const CString& sNet, const CString& sTarget, const CString& sDay, const std::vector<IndexRow>& v,
                    long long lBytes) {
        if (!Begin()) return false;
        bool bOk = DeleteDay(sNet, sTarget, sDay, false);
        for (size_t i = 0; bOk && i < v.size(); i++) bOk = Insert(v[i]);
        bOk = bOk && SetDay(sNet, sTarget, sDay, lBytes);
        if (!bOk) { Rollback(); return false; }
        return Commit();
    }

    bool DeleteMsg(const CString& sNet, const CString& sTarget, const CString& sMsgId) {
        sqlite3_stmt* st = Stmt("DELETE FROM msg WHERE network=? AND target=? AND msgid=?");
        if (!st) return false;
        Bind(st, 1, sNet); Bind(st, 2, sTarget); Bind(st, 3, sMsgId);
        return Step(st);
    }

    // Forget every size record: the next sync re-reads all files.
    bool ForgetDays() { return Exec("DELETE FROM days"); }

    // ---- reading ----------------------------------------------------------

    // DayKey(network, target, day) -> indexed bytes, for one network ("" = all).
    static CString DayKey(const CString& sNet, const CString& sTarget, const CString& sDay) {
        return sNet + "\n" + sTarget + "\n" + sDay;
    }
    std::map<CString, long long> DaySizes(const CString& sNet) {
        std::map<CString, long long> m;
        sqlite3_stmt* st = Stmt("SELECT network, target, day, bytes FROM days WHERE network=? OR ?='' ");
        if (!st) return m;
        Bind(st, 1, sNet); Bind(st, 2, sNet);
        while (sqlite3_step(st) == SQLITE_ROW)
            m[DayKey(Col(st, 0), Col(st, 1), Col(st, 2))] = sqlite3_column_int64(st, 3);
        sqlite3_reset(st);
        return m;
    }

    bool Search(const SearchSpec& spec, std::vector<IndexHit>& out, bool& bTruncated) {
        bTruncated = false;
        if (!m_pDb) return false;
        const CString sCols = "m.target, m.day, m.time, m.msgid, m.off, m.len";
        const CString sOrder = spec.bForward ? "ASC" : "DESC";
        CString sSql;
        struct Param { bool bInt; CString s; long long l; };
        std::vector<Param> vsBind;
        auto text = [&](const CString& v) { vsBind.push_back({false, v, 0}); };
        auto integer = [&](long long v) { vsBind.push_back({true, "", v}); };
        auto filters = [&](const CString& sIdCol) {
            sSql += " AND m.network=?";
            text(spec.sNetwork);
            if (!spec.sTarget.empty()) { sSql += " AND m.target=?"; text(spec.sTarget); }
            if (!spec.sNick.empty()) { sSql += " AND m.nick=?"; text(spec.sNick); }
            // Coarse rowid bounds (seconds) narrow the index walk; the exact
            // comparison on the stored time keeps millisecond semantics.
            if (!spec.sAfter.empty()) {
                sSql += " AND " + sIdCol + ">=? AND m.time>=?";
                integer(IdBase(TimeSeconds(spec.sAfter)));
                text(spec.sAfter);
            }
            if (!spec.sBefore.empty()) {
                sSql += " AND " + sIdCol + "<? AND m.time<=?";
                integer(IdBase(TimeSeconds(spec.sBefore) + 1));
                text(spec.sBefore);
            }
        };
        if (spec.sText.empty()) {
            sSql = "SELECT " + sCols + " FROM msg m WHERE 1=1";
            filters("m.id");
            sSql += " ORDER BY m.id " + sOrder + " LIMIT ?";
        } else if (Utf8Length(spec.sText) >= 3) {
            CString sMatch = "loc:\"" + LocToken(spec.sNetwork, spec.sTarget) + "\"";
            if (!spec.sNick.empty()) sMatch += " AND who:\"" + HashToken(spec.sNick) + "\"";
            sMatch += " AND text:\"" + spec.sText.Replace_n("\"", "\"\"") + "\"";
            sSql = "SELECT " + sCols + " FROM fts JOIN msg m ON m.id = fts.rowid WHERE fts MATCH ?";
            text(sMatch);
            filters("fts.rowid");
            sSql += " ORDER BY fts.rowid " + sOrder + " LIMIT ?";
        } else {
            sSql = "SELECT " + sCols + " FROM msg m WHERE instr(lower(m.text), ?) > 0";
            text(spec.sText.AsLower());
            filters("m.id");
            sSql += " ORDER BY m.id " + sOrder + " LIMIT ?";
        }
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(m_pDb, sSql.c_str(), -1, &st, nullptr) != SQLITE_OK) return false;
        for (size_t i = 0; i < vsBind.size(); i++) {
            if (vsBind[i].bInt) sqlite3_bind_int64(st, (int)i + 1, vsBind[i].l);  // rowid bounds stay integers
            else Bind(st, (int)i + 1, vsBind[i].s);
        }
        sqlite3_bind_int64(st, (int)vsBind.size() + 1, (sqlite3_int64)spec.uLimit);

        const auto tDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(spec.lMaxMillis);
        sqlite3_progress_handler(m_pDb, 1000, &SearchIndex::Progress, (void*)&tDeadline);
        int rc;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            IndexHit h;
            h.sTarget = Col(st, 0); h.sDay = Col(st, 1); h.sTime = Col(st, 2); h.sMsgId = Col(st, 3);
            h.lOff = sqlite3_column_int64(st, 4); h.lLen = sqlite3_column_int64(st, 5);
            out.push_back(std::move(h));
        }
        sqlite3_progress_handler(m_pDb, 0, nullptr, nullptr);
        sqlite3_finalize(st);
        if (rc == SQLITE_INTERRUPT) { bTruncated = true; return true; }
        return rc == SQLITE_DONE;
    }

    long long CountRows() {
        sqlite3_stmt* st = Stmt("SELECT count(*) FROM msg");
        long long n = -1;
        if (st && sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int64(st, 0);
        if (st) sqlite3_reset(st);
        return n;
    }

    int SchemaVersion() {
        sqlite3_stmt* st = Stmt("SELECT value FROM meta WHERE key='schema'");
        int v = 0;
        if (st && sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int(st, 0);
        if (st) sqlite3_reset(st);
        return v;
    }

  private:
    static int Progress(void* p) {
        const auto* pDeadline = static_cast<const std::chrono::steady_clock::time_point*>(p);
        return std::chrono::steady_clock::now() > *pDeadline ? 1 : 0;
    }

    // Sets bRecreate (and returns true without changing anything) when an
    // existing database needs a "recreate" migration.
    bool Migrate(CString& sError, bool& bRecreate) {
        if (!Exec("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID")) {
            sError = LastError();
            return false;
        }
        int iVersion = SchemaVersion();
        if (iVersion > kSchemaVersion) {
            sError = "index schema " + CString(iVersion) + " is newer than this module (" + CString(kSchemaVersion) + ")";
            return false;
        }
        if (iVersion > 0)
            for (const Migration& m : Migrations())
                if (m.iTo > iVersion && m.bRecreate) { bRecreate = true; return true; }
        for (const Migration& m : Migrations()) {
            if (m.iTo <= iVersion) continue;
            // IMMEDIATE takes the write lock first: another connection (the
            // sync thread) may be applying the same migration right now.
            if (!Exec("BEGIN IMMEDIATE")) { sError = LastError(); return false; }
            if (SchemaVersion() >= m.iTo) { Exec("COMMIT"); iVersion = SchemaVersion(); continue; }
            CString sSet = "INSERT OR REPLACE INTO meta(key, value) VALUES('schema', '" + CString(m.iTo) + "')";
            if (!Exec(m.sSql) || !Exec(sSet.c_str())) {
                sError = "migration to schema " + CString(m.iTo) + " failed: " + LastError();
                Rollback();
                return false;
            }
            if (!Exec("COMMIT")) { sError = LastError(); return false; }
            iVersion = m.iTo;
        }
        return true;
    }

    sqlite3_stmt* Stmt(const char* sSql) {
        if (!m_pDb) return nullptr;
        auto it = m_mStmts.find(sSql);
        if (it != m_mStmts.end()) {
            sqlite3_reset(it->second);
            sqlite3_clear_bindings(it->second);
            return it->second;
        }
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(m_pDb, sSql, -1, &st, nullptr) != SQLITE_OK) return nullptr;
        m_mStmts[sSql] = st;
        return st;
    }
    static void Bind(sqlite3_stmt* st, int i, const CString& s) {
        sqlite3_bind_text(st, i, s.c_str(), (int)s.size(), SQLITE_TRANSIENT);
    }
    static CString Col(sqlite3_stmt* st, int i) {
        const unsigned char* p = sqlite3_column_text(st, i);
        return p ? CString((const char*)p, (size_t)sqlite3_column_bytes(st, i)) : CString();
    }
    bool Step(sqlite3_stmt* st) {
        int rc = sqlite3_step(st);
        sqlite3_reset(st);
        return rc == SQLITE_DONE || rc == SQLITE_ROW;
    }

    sqlite3* m_pDb = nullptr;
    CString m_sPath;
    std::map<CString, sqlite3_stmt*> m_mStmts;
};

}  // namespace ircv3
