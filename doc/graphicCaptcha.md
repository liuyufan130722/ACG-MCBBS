# 图形验证码接口文档

本文档描述了生成和验证图形验证码的API接口。

## 生成图形验证码

### POST `/generate_graphic_captcha`

生成一个图形验证码图片。

#### 请求参数
无

#### 响应
- **200 OK** - 成功生成验证码
  - `code` - 状态码 (200 / 404)
  - `content` - 验证码图片的url

### GET `/generate_graphic_captcha`

同上。

## 验证图形验证码

### POST `/verify_graphic_captcha`

验证用户输入的验证码是否正确。

#### 请求参数
- `code` (string) - 用户输入的验证码

#### 响应
- **200 OK** - 验证成功
  - `code` - 200
  - `content` - "message"
- **400 Bad Request** - 验证码错误或不存在
  - `code` - 404
  - `content` - "message"


### GET `/verify_graphic_captcha`

同上，但通常验证操作使用POST方法更为合适。

## 示例代码

在 URL： `/graphic_validation`

### 验证验证码

```http
POST /verify_graphic_captcha
Content-Type: application/json

{
  "code": "USER_INPUT_CODE"
}
```

### 响应示例

验证成功：

```json
{
  "code": 200,
  "message": "success"
}
```

验证失败：

```json
{
  "code": 404,
  "message": "fail"
}
```

## 注意事项

- 请确保在生成和验证过程中使用相同的验证码ID。
- 验证码图片以`URL`格式返回，可直接用于前端展示。
- 验证接口应仅接受POST请求，以保护用户输入的安全。