// D1 兼容层：把 Cloudflare D1 的接口映射到 node:sqlite。
// 后端逻辑完全不需要改，只替换 env.cijing_db 的实现。
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";

function normalize(value) {
  if (value === undefined || value === null) return null;
  if (typeof value === "boolean") return value ? 1 : 0;
  if (typeof value === "object") return JSON.stringify(value);
  return value;
}

class Statement {
  constructor(db, sql) {
    this.db = db;
    this.sql = sql;
    this.params = [];
  }

  bind(...params) {
    this.params = params.map(normalize);
    return this;
  }

  async first() {
    const row = this.db.prepare(this.sql).get(...this.params);
    return row === undefined ? null : row;
  }

  async all() {
    return { results: this.db.prepare(this.sql).all(...this.params) };
  }

  async run() {
    const info = this.db.prepare(this.sql).run(...this.params);
    return {
      success: true,
      meta: {
        changes: Number(info.changes) || 0,
        last_row_id: Number(info.lastInsertRowid) || 0,
      },
    };
  }
}

export class D1Database {
  constructor(sqlite) {
    this.sqlite = sqlite;
  }

  prepare(sql) {
    return new Statement(this.sqlite, sql);
  }

  // D1 的 batch 是事务语义：要么全部成功，要么全部回滚
  async batch(statements) {
    const isRead = (sql) => /^\s*(SELECT|WITH|PRAGMA|EXPLAIN)/i.test(sql);
    this.sqlite.exec("BEGIN");
    try {
      const out = [];
      for (const statement of statements) {
        const prepared = this.sqlite.prepare(statement.sql);
        if (isRead(statement.sql)) {
          out.push({ success: true, results: prepared.all(...statement.params), meta: { changes: 0 } });
        } else {
          const info = prepared.run(...statement.params);
          out.push({
            success: true,
            results: [],
            meta: { changes: Number(info.changes) || 0, last_row_id: Number(info.lastInsertRowid) || 0 },
          });
        }
      }
      this.sqlite.exec("COMMIT");
      return out;
    } catch (error) {
      this.sqlite.exec("ROLLBACK");
      throw error;
    }
  }
}

export function openDatabase({ path, schemaPath }) {
  const sqlite = new DatabaseSync(path);
  sqlite.exec("PRAGMA journal_mode = WAL;");
  // schema.sql 全是 IF NOT EXISTS，可以每次启动安全执行
  sqlite.exec(readFileSync(schemaPath, "utf8"));
  return sqlite;
}
