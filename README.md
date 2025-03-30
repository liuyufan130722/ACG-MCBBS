# ACG-MCBBS 论坛

## 功能特性
- 用户注册（含邮箱验证码）
- 头像上传与显示
- 密码哈希存储
- 帖子发布与浏览
- 响应式二次元风格界面

## 1.Preparatory Work

### You should have the following:

1.A Server(if you don't have this,You can use a idle computer(also can use Raspberry Pi))

2.A FRP software

3.A usable hand

4.Linux operating experience

5.A ssh software

6.A sftp software

7.Your PC

## 2.Begin Deploy

### The first,use your PC to connect to the server via ssh,It look like

```bash
ssh <your_username>@<server_ip>
```

### Then,enter your password.(Attention! Input is invisible in this process, and deletion can be used normally)

### OK,Now you can enter command to your server,Send the project file up with sftp software.

```bash
cd <your_project_dirctory>
pip3 install virtualenv
virtualenv venv
source ./virtualenv/bin/activate
#if you want to disable virtualenv,you can enter source ./virtualenv/bin/activate
pip3 install -r requirements.txt
python3 app.py
```

## 3.Safe

### install line WAF

```bash
bash -c "$(curl -fsSLk https://waf-ce.chaitin.cn/release/latest/manager.sh)"
```

### install Hfish

```bash
bash <(curl -sS -L https://hfish.net/webinstall.sh)
```

### install 1panel

```bash
curl -sSL https://resource.fit2cloud.com/1panel/package/quick_start.sh -o quick_start.sh && sh quick_start.sh
```

###### © 2024-2025 XG-Studio. All rights reserved.

###### 禁止在未经XG-Studio授权前使用本文档，否则XG-Studio有权利收回您的授权。

###### Version: 1.0
