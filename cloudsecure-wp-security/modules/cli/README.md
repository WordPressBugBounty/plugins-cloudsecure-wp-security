# CloudSecure WP Security CLI Commands

このドキュメントでは、CloudSecure WP Security プラグインのWP-CLIコマンドの使用方法について説明します。

## インストール

プラグインが有効化されていれば、自動的にWP-CLIコマンドが利用可能になります。

## 基本コマンド

### 利用可能な機能一覧を表示

```bash
wp cldsec-wp-security list
```

**レスポンス形式:**
```json
{
  "result": "success",
  "data": [
    {
      "name": "disable-login",
      "description": "ログイン無効化",
      "status": "enabled"
    },
  ]
}
```

### 特定機能の詳細状態を確認

```bash
wp cldsec-wp-security status <機能名>
```

**例:**
```bash
wp cldsec-wp-security status disable-login
```

**レスポンス形式:**
```json
{
  "result": "success",
  "data": {
    "name": "disable-login",
    "description": "ログイン無効化", 
    "status": "enabled",
    "configuration": {
      "interval": "5",
      "limit": "5",
      "duration": "300"
    }
  }
}
```

**注意事項:**
- 機能名は必須です (単一の機能名のみ受付、複数指定はエラー)
- `--option=value` 形式のオプション引数は渡されても使用しません

### 機能の有効化

```bash
wp cldsec-wp-security enable <機能名> [--設定項目=値]
```

**例:**
```bash
wp cldsec-wp-security enable disable-login --interval=5 --limit=5 --duration=300
```

**注意事項:**
- 機能名は必須です(単一の機能名のみ受付、複数指定はエラー)

### 機能の無効化

```bash
wp cldsec-wp-security disable <機能名>
```

**例:**
```bash
wp cldsec-wp-security disable disable-login
```

**レスポンス例:**
```json
{
  "result": "success",
  "message": "ログイン無効化機能が無効になりました。"
}
```

**注意事項:**
- 機能名は必須です(単一の機能名のみ受付、複数指定はエラー)
- `--option=value` 形式のオプション引数は渡されても使用しません

## 利用可能な機能と設定項目

### disable-login (ログイン無効化)
```bash
wp cldsec-wp-security enable disable-login --interval=5 --limit=5 --duration=300
```

**設定項目と設定可能な値:**

| オプション      | 説明                 | 設定可能な値                |
|----------------|----------------------|----------------------------|
| --interval     | 間隔(秒)             | 5, 15, 30                  |
| --limit        | ログイン失敗回数      | 5, 15, 30                  |
| --duration     | ログイン無効時間(秒)  | 60, 180, 300, 600, 3600    |


### rename-login-page (ログインURL変更)
```bash
wp cldsec-wp-security enable rename-login-page --name=custom-login --disable_redirect=0
```

**設定項目と設定可能な値:**

| オプション           | 説明                   | 設定可能な値                    |
|----------------------|-----------------------|--------------------------------|
| --name               | 変更後のログインURL    | 4-12文字、英小文字・数字・-・_   |
| --disable_redirect   | リダイレクト設定       | 0(リダイレクトする), 1(しない)   |


### unify-messages (ログインエラーメッセージ統一)
```bash
wp cldsec-wp-security enable unify-messages
```
**設定項目と設定可能な値:**
設定項目なし (有効/無効のみ)

### two-factor-authentication (2段階認証)
```bash
wp cldsec-wp-security enable two-factor-authentication --enabled_roles=administrator,editor
```

**設定項目と設定可能な値:**

| オプション         | 説明                         | 設定可能な値                                               |
|--------------------|-----------------------------|-----------------------------------------------------------|
| --enabled_roles    | 2段階認証が有効な権限グループ | administrator, editor など(カンマ区切り、カスタム権限も含む)  |

**注意事項:**
statusコマンドやenableコマンド実行時のレスポンスには、設定項目に加えて`user_registrations`項目も含まれます。この項目には各ユーザーの2段階認証設定状況(1:設定済、0:未設定)が表示されます。

**レスポンス例:**
```json
{
  "result": "success",
  "data": {
    "message": "2段階認証機能が有効になりました。",
    "status": "enabled",
    "configuration": {
      "enabled_roles": "editor",
  "user_registrations": "user1:0,user2:0,user3:1"
    }
  }
}
```


### captcha (画像認証追加)
```bash
wp cldsec-wp-security enable captcha --login=2 --comment=1 --lost_password=2 --register=2
```

**設定項目と設定可能な値:**

| オプション         | 説明                       | 設定可能な値         |
|--------------------|----------------------------|--------------------|
| --login            | ログインフォーム           | 1(無効), 2(有効)     |
| --comment          | コメントフォーム           | 1(無効), 2(有効)     |
| --lost_password    | パスワードリセットフォーム | 1(無効), 2(有効)     |
| --register         | ユーザー登録フォーム       | 1(無効), 2(有効)     |

### restrict-admin-page (管理画面アクセス制限)
```bash
wp cldsec-wp-security enable restrict-admin-page --paths="css,images,admin-ajax.php"
```

**設定項目と設定可能な値:**

| オプション   | 説明         | 設定可能な値                                   |
|--------------|-------------|-----------------------------------------------|
| --paths      | 除外パス     | 例: css,images,admin-ajax.php(カンマ区切り)    |


### disable-access-system-file (設定ファイルアクセス防止)
```bash
wp cldsec-wp-security enable disable-access-system-file
```
**設定項目と設定可能な値:**
設定項目なし (有効/無効のみ)

### disable-author-query (ユーザー名漏えい防止)
```bash
wp cldsec-wp-security enable disable-author-query
```
**設定項目と設定可能な値:**
設定項目なし (有効/無効のみ)

### disable-xmlrpc (XML-RPC無効化)
```bash
wp cldsec-wp-security enable disable-xmlrpc --type=2
```

**設定項目と設定可能な値:**

| オプション   | 説明         | 設定可能な値                           |
|--------------|--------------|--------------------------------------|
| --type       | 無効化種別   | 1(ピンバック無効), 2(XML-RPC無効)      |

**レスポンス例:**
```bash
# ピンバック無効の場合
wp cldsec-wp-security enable disable-xmlrpc --type=1
```
```json
{
  "result": "success",
  "data": {
    "message": "ピンバック無効化機能が有効になりました。",
    "status": "enabled",
    "configuration": {
      "type": "1"
    }
  }
}
```

```bash
# XML-RPC無効の場合  
wp cldsec-wp-security enable disable-xmlrpc --type=2
```
```json
{
  "result": "success",
  "data": {
    "message": "XML-RPC無効化機能が有効になりました。",
    "status": "enabled",
    "configuration": {
      "type": "2"
    }
  }
}
```

### disable-restapi (REST API無効化)
```bash
wp cldsec-wp-security enable disable-restapi --exclude="wp/v2/users,wp/v2/posts"
```

**設定項目と設定可能な値:**

| オプション   | 説明           | 設定可能な値                                      |
|--------------|---------------|--------------------------------------------------|
| --exclude    | 除外プラグイン | 例: oembed,contact-form-7,akismet(カンマ区切り)   |


### waf (シンプルWAF)
```bash
wp cldsec-wp-security enable waf --available_rules="sql,xss,command" --send_admin_mail=2
```

**設定項目と設定可能な値:** 設定項目なし (有効/無効のみ)

| オプション           | 説明              | 設定可能な値                                  |
|----------------------|-----------------|-----------------------------------------------|
| --available_rules    | 検知する攻撃種別  | sql, xss, command, code, mail(カンマ区切り)   |
| --send_admin_mail    | メール通知       | 1(通知しない), 2(通知する)                     |


### login-notification (ログイン通知)
```bash
wp cldsec-wp-security enable login-notification --subject="ログイン通知" --body="ログインしました" --admin_only=1
```

**設定項目と設定可能な値:**

| オプション      | 説明             | 設定可能な値                             |
|-----------------|-----------------|-----------------------------------------|
| --subject       | サブジェクト     | 任意の文字列                             |
| --body          | メール本文       | 任意の文字列(改行は`__CLDSEC_NEWLINE__`) |
| --admin_only    | 受信者          | 0(全員に通知), 1(管理者のみ通知)          |


### update-notice (アップデート通知)
```bash
wp cldsec-wp-security enable update-notice --wp=1 --plugin=3 --theme=2
```

**設定項目と設定可能な値:**

| オプション   | 説明                   | 設定可能な値                                                          |
|--------------|-----------------------|----------------------------------------------------------------------|
| --wp         | WordPressアップデート  | 1(通知しない), 2(通知する)                                             |
| --plugin     | プラグインアップデート  | 1(通知しない), 2(すべて通知する), 3(有効化されたプラグインのみ通知する)   |
| --theme      | テーマアップデート     | 1(通知しない), 2(すべて通知する), 3(有効化されたテーマのみ通知する)       |


### server-error-notification (サーバーエラー通知)
```bash
wp cldsec-wp-security enable server-error-notification --email_notification=1
```

**設定項目と設定可能な値:**

| オプション              | 説明                   | 設定可能な値                 |
|------------------------|------------------------|-----------------------------|
| --email_notification   | メールで通知する        | 0(通知しない), 1(通知する)    |

## 特別なコマンド

### REST API無効化の専用操作

#### 有効プラグイン一覧の取得
```bash
wp cldsec-wp-security disable-restapi list-plugins
```

**説明:**
REST API無効化機能で除外指定していない有効なプラグインの一覧を取得します。

**レスポンス例:**
```json
{
  "result": "success",
  "data": {
    "active_plugin_names": "plugin1,plugin2,plugin3"
  }
}
```

## レスポンス形式

すべてのコマンドは統一されたJSON形式でレスポンスを返します：

**成功時:**
```json
{
  "result": "success",
  "data": { ... }
}
```

**エラー時:**
```json
{
  "result": "error", 
  "data": {
    "message": "エラーメッセージ"
  }
}
```

## トラブルシューティング

### 設定項目や値のエラーについて

間違った設定項目名や設定値を指定した場合、エラーメッセージで利用可能な項目や値が表示されます。

**存在しない設定項目を指定した場合:**
```bash
wp cldsec-wp-security enable disable-login --test
```
```json
{
  "result": "error",
  "data": {
    "message": "機能 'disable-login' には設定項目 'test' は存在しません。利用可能な設定項目: interval, limit, duration"
  }
}
```

**無効な設定値を指定した場合:**
```bash
wp cldsec-wp-security enable disable-login --interval=100
```
```json
{
  "result": "error",
  "data": {
    "message": "intervalは次のいずれかの値を指定してください: 5, 15, 30"
  }
}
```

## 利用可能な機能一覧

| 機能名 | 説明 | 設定項目の有無 |
|--------|------|---------------|
| `disable-login` | ログイン無効化 | ✅ |
| `rename-login-page` | ログインURL変更 | ✅ |
| `unify-messages` | ログインエラーメッセージ統一 | ❌ |
| `two-factor-authentication` | 2段階認証 | ✅ |
| `captcha` | 画像認証追加 | ✅ |
| `restrict-admin-page` | 管理画面アクセス制限 | ✅ |
| `disable-access-system-file` | 設定ファイルアクセス防止 | ❌ |
| `disable-author-query` | ユーザー名漏えい防止 | ❌ |
| `disable-xmlrpc` | XML-RPC無効化 | ✅ |
| `disable-restapi` | REST API無効化 | ✅ |
| `waf` | シンプルWAF | ✅ |
| `login-notification` | ログイン通知 | ✅ |
| `update-notice` | アップデート通知 | ✅ |
| `server-error-notification` | サーバーエラー通知 | ✅ |

**注意**: `login-log`(ログイン履歴)は設定値が存在しないため、status,enable,disableコマンドでは操作できません。
