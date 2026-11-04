# WinOwner MCP

**Máy Windows của bạn. AI của bạn. Quyền kiểm soát của bạn.**

WinOwner MCP là agent cho phép AI được chủ máy xác thực thực hiện công việc lập trình và điều khiển Windows từ xa thông qua giao thức MCP.

[English](README.md) · [Hướng dẫn cài đặt](docs/INSTALLATION.md) · [Kết nối ChatGPT](docs/CONNECT_CHATGPT.md) · [Bảo mật](SECURITY.md)

> **Bản RC thử nghiệm, có quyền tác động tới máy tính.** Agent thực thi trong phạm vi quyền của tài khoản Windows chạy nó; đây không phải sandbox và chưa được kiểm toán bảo mật độc lập.

## Chức năng

- **Lập trình từ xa:** đọc mã nguồn, tìm kiếm, sửa file, chạy PowerShell và pytest, kiểm tra Git.
- **Xác thực chủ máy:** OAuth 2.1, PKCE S256, cấp quyền theo phạm vi và cơ chế thu hồi.
- **Sửa đổi có thể kiểm tra:** SHA-256 trước khi thay đổi file, backup và nhật ký audit.
- **Điều khiển Windows:** chuột, bàn phím, cửa sổ và tác vụ khi có quyền phù hợp.
- **Bảo vệ vận hành:** mặc định `read_only`, console quản trị và dừng khẩn cấp.

## Tương thích AI client

| Client | Trạng thái |
|---|---|
| ChatGPT | Đã nghiệm thu trên hệ thống RC3 của chủ máy |
| Claude, Cursor, Codex và MCP client khác | Chưa nghiệm thu, chưa cam kết hỗ trợ |

## Cài đặt hiện tại

Trên Windows 10/11, dùng Git và Python 3.12+, chạy PowerShell trong một thư mục thử nghiệm:

```powershell
git clone https://github.com/phuonghuster7/winowner-mcp.git
cd winowner-mcp
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Install-WindowsMcpAgent.ps1 -DryRun
```

Lệnh `-DryRun` chỉ kiểm tra điều kiện, **chưa ghép nối OAuth/tunnel**. Tính năng cài read-only một dòng đang được nghiệm thu ở [PR #9](https://github.com/phuonghuster7/winowner-mcp/pull/9), chưa có trong RC3 chính thức.

## Phân quyền và giới hạn

- `READ`: đọc, tìm kiếm, kiểm tra Git; mặc định được bật.
- `WRITE`, `EXECUTE`, `DESKTOP`: cần ủy quyền hợp lệ.
- `SYSTEM_ADMIN`: mặc định từ chối.
- `OWNER_GLOBAL_FILESYSTEM`: chỉ bật khi chủ máy chủ động cấp quyền; không vượt qua NTFS/UAC.
- Lọc lệnh bằng biểu thức chính quy chỉ là cơ chế giảm thao tác nhầm, **không phải sandbox**.
- Một số test live auth, desktop và rollback chưa nằm trong CI tự động; chưa nghiệm thu rộng rãi trên Windows sạch.

Đọc [SECURITY.md](SECURITY.md) và [hướng dẫn kết nối](docs/CONNECT_CHATGPT.md) trước khi mở quyền truy cập từ xa.

Dự án độc lập, không liên kết hay được bảo trợ bởi Microsoft hoặc OpenAI. Giấy phép MIT.
