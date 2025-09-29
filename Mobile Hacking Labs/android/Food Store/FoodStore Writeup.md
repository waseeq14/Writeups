# FoodStore - SQL Injection

**Objective:** Exploit a SQL Injection vulnerability in the signup function of the Android app to register a Pro user (10,000 credits) and bypass normal restrictions.

---

## Environment

- Android app: `com.mobilehackinglab.foodstore`
    
- Vulnerable class: `DBHelper` (uses `SQLiteOpenHelper` and `execSQL` with string concatenation)
    
- DB: `userdatabase.db`, table `users(id, username, password, address, isPro)`
    

---

## Vulnerable code 
![[Screenshot 2025-09-29 at 10.40.52 AM.png]]

```java
String sql = "INSERT INTO users (username, password, address, isPro) VALUES ('" + Username + "', '" + encodedPassword + "', '" + encodedAddress + "', 0)";
db.execSQL(sql);
```

**Why it is vulnerable:** the `Username` value is concatenated directly into the SQL statement inside single quotes. An attacker-controlled string can therefore **close the open quote**, inject arbitrary SQL (for example a VALUES tuple that sets `isPro = 1`), and comment out the remainder, resulting in an attacker-specified row being inserted. By default, `isPro` is being set to 0.

---

## Attack strategy

Two practical approaches were considered and tested:

1. **Tuple injection (single statement):** Close the username string, provide a full `VALUES(...)` tuple including Base64-encoded `password` and `address`, set `isPro = 1`, then comment out the rest. This works reliably because it needs only a single SQL statement.
    
2. **Second-statement injection:** Close the string and inject an additional `UPDATE` statement to flip `isPro` on an existing account. This requires execution of multiple statements; it works when the SQLite engine and `execSQL` allow multiple statements.
    

Tuple injection is preferred for reliability.

---

## Payload used 
![[Screenshot 2025-09-29 at 10.37.55 AM.png]]

When registering in the app, the following string was entered in the **username** field:

```
gus', 'cGFzc3dvcmQ=', 'YWRkcg==', 1); --
```

**Notes:**

- All quotes are plain ASCII single quotes (`'`).
    
- `cGFzc3dvcmQ=` is Base64 of `password`.
    
- `YWRkcg==` is Base64 of `addr`.
    
- The `--` starts a comment and comments out the remainder of the original SQL the app appended.
    

### Why Base64?

The app encodes the password and address with Base64 before inserting. When `getUserByUsername()` runs it Base64-decodes the stored values. Because this injection supplies the column values directly, the injected password/address must be Base64-encoded so the app’s decode step yields the intended plaintext credentials.

---

## Conceptual resulting SQL

Given the app's concatenation, after injection the executed SQL (conceptually) becomes:

```
INSERT INTO users (username, password, address, isPro) VALUES ('gus', 'cGFzc3dvcmQ=', 'YWRkcg==', 1); --', '<ENC_PW_FROM_APP>', '<ENC_ADDR_FROM_APP>', 0)
```

Everything after `--` is ignored, so the DB inserts the attacker-specified row with `isPro = 1`.

---

## Verification / login

- Username: `gus`
    
- Password: `password` (because `cGFzc3dvcmQ=` decodes to `password`)
    
- Address: `addr` (because `YWRkcg==` decodes to `addr`)
![[Screenshot 2025-09-29 at 10.39.14 AM.png]]

Login using the app’s login flow with `gus` / `password` — the account shows as **Pro**. (10,000 credits)

---

## Mitigations / remediation

1. **Use parameterized queries or prepared statements** (never concatenate user input into SQL). Example using `ContentValues` / `db.insert(...)` or `SQLiteStatement` with bound parameters.
    
2. **Never store passwords reversible or in cleartext.** Use a secure password hashing function (e.g., `bcrypt`, `PBKDF2`, `Argon2`) with a per-account salt. Do not use Base64 for password storage — Base64 is _encoding_, not hashing or encryption.
    
3. **Sanitize and validate inputs** on the server side (and treat client-side validation as insufficient). But note: input validation is not a replacement for parameterized queries.
    
4. **Limit SQL execution rights and harden the DB.** Do not rely on app-side protections to prevent injection; assume inputs are hostile.
    
5. **Avoid executing multiple statements from a single untrusted string.** If the runtime disallows multiple statements that helps but is not a substitute for proper parameterization.
    
6. **Secure sensitive fields in transit and at rest.** If address or other PII must be stored, consider proper encryption (not Base64).
    
7. **Add logging/alerts** for suspicious DB modifications in production.
    

---
