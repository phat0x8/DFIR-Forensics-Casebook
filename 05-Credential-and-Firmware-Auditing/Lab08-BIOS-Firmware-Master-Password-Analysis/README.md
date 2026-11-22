# Lab 08: Firmware Forensics – BIOS Master Password Recovery Mechanisms
### *Phân tích Cơ chế Khôi phục Mật khẩu BIOS/Firmware Phục vụ Thu thập Bằng chứng*

[⬅️ Back to Main DFIR Casebook](../../README.md)

---

## 📌 Quick Metadata

| Field | Description |
| :--- | :--- |
| **Forensic Environment** | `Kali Linux 2025.4 / 2026.3 (64-bit)` on `VMware Workstation Pro` (Host: `Windows 11`) |
| **Forensic Module** | `05-Credential-and-Firmware-Auditing` |
| **Target Dataset / Evidence** | `VirtualBox / VM Firmware Environment & Master Password Generation Algorithms (bios-pwgen)` |
| **Core Forensic Toolstack** | `bios-pwgen (Python/C algorithms for Dell, Asus, FSI, Insyde, Samsung, Sony), System Disabled Hash Analysis` |
| **MITRE ATT&CK / DFIR Focus** | `Hardware/Firmware Access Recovery for Lawful Forensic Acquisition` |

---

## 1. Tổng quan & Bối cảnh Điều tra (Overview & Objectives)

### 1.1. Bối cảnh và Mục tiêu

Bài lab mô phỏng quá trình thiết lập mật khẩu BIOS trên máy ảo VMware và thực hiện quy trình bypass (vượt qua) mật khẩu này. Mục tiêu là hiểu rõ cơ chế bảo mật của BIOS (Supervisor Password, Password on boot), cách hệ thống phản hồi khi nhập sai mật khẩu nhiều lần (System Disabled), và cách sử dụng công cụ keygen để tạo mật khẩu chủ (master password) từ mã lỗi. Từ đó, sinh viên nắm được lỗ hổng bảo mật của BIOS máy tính và cách khắc phục.

### 1.2. Môi trường và Công cụ Thực hành

| Thành phần | Tên / Phiên bản | Ghi chú (cấu hình, nguồn tải…) |
| --- | --- | --- |
| Máy thật (host) – hệ điều hành | Windows 11 |  |
| Phần mềm ảo hoá | VMware Workstation |  |
| Máy ảo sử dụng | Windows 10 |  |
| Công cụ điều tra 1 | Phoenix BIOS Setup Utility | Môi trường BIOS của VM |
| Công cụ điều tra 2 | pwgen-5dec (Keygen) | Tạo master password |

## 2. Quy trình Điều tra & Thực nghiệm Kỹ thuật (Forensic Investigation Workflow)

### Bước 1. Thiết lập mật khẩu BIOS (Assigning a BIOS Password)

**a) Mô tả thao tác:** Mở VMware, chọn VM > Power > Power On to BIOS. Tại tab Security, chọn Set Supervisor Password, nhập 12345678 vào 2 ô và nhấn Enter. Nhấn F10 để lưu, sau đó tắt máy ảo (Power Off)

**b) Câu lệnh / cấu hình đã sử dụng:**Không có

**c) Ảnh minh chứng:**

![Forensic Evidence Figure 01](assets/fig_01.png)

*Hình 1.1. Cửa sổ Set Supervisor Password. Cửa sổ Set Supervisor Password*

![Forensic Evidence Figure 02](assets/fig_02.png)

*Hình 1.2. Thông báo đã thay đổi thay đổi mật khẩu thành công*

![Forensic Evidence Figure 03](assets/fig_03.png)

*Hình 1.3. Trạng thái Supervisor Password Is: Set*

![Forensic Evidence Figure 04](assets/fig_04.png)

*Hình 1.4. Màn hình xác nhận lưu cấu hình mật khẩu Supervisor và thoát*

**d) Kết quả & diễn giải:** Mật khẩu BIOS được thiết lập thành công (trạng thái chuyển từ Clear sang Set), yêu cầu nhập mật khẩu khi truy cập BIOS

### Bước 2. Kích hoạt lỗi System Disabled

**a) Mô tả thao tác:** Khởi động lại máy ảo vào BIOS bằng cách chọn VM > Power > Power On to BIOS. Tại hộp thoại Enter Password, nhập sai mật khẩu (ví dụ: X) và nhấn Enter 3 lần liên tiếp. Hệ thống sẽ hiển thị màn hình System Disabled kèm theo mã code (ví dụ: 11805)

**b) Câu lệnh / cấu hình đã sử dụng :** Không có

**c) Ảnh minh chứng:**

![Forensic Evidence Figure 05](assets/fig_05.png)

*Hình 2.1. Chọn chế độ khởi động vào BIOS từ thanh menu của VMware*

![Forensic Evidence Figure 06](assets/fig_06.png)

*Hình 2.2. Hộp thoại yêu cầu nhập mật khẩu BIOS*

![Forensic Evidence Figure 07](assets/fig_07.png)

*Hình 2.3. Cảnh báo nhập sai mật khẩu (Invalid Password)*

![Forensic Evidence Figure 08](assets/fig_08.png)

*Hình 2.4. Màn hình System Disabled hiển thị mã code 11805*

![Forensic Evidence Figure 09](assets/fig_09.png)

*Hình 2.5. Lưu ảnh chụp màn hình System Disabled thành file ảnh*

**d) Kết quả & diễn giải:** Hệ thống đã kích hoạt cơ chế bảo vệ khóa màn hình sau 3 lần nhập sai. Mã code 11805 xuất hiện trên màn hình chính là dữ liệu đầu vào quan trọng để phần mềm keygen tính toán ra mật khẩu chủ ở bước tiếp theo.

### Bước 3. Tải và chạy công cụ Keygen

**a) Mô tả thao tác:** Mở trình duyệt web, truy cập trang web dogber1.blogspot.com để tìm bảng mã BIOS. Tìm dòng Phoenix (generic) và tải file Windows binary (hoặc nhận file pwgen-5dec.zip từ giảng viên). Giải nén file zip, mở thư mục và chạy file pwgen-5dec.exe. Một cửa sổ Command Prompt sẽ hiện ra.

**b) Câu lệnh / cấu hình đã sử dụng :** Không có

**c) Ảnh minh chứng:**

![Forensic Evidence Figure 10](assets/fig_10.png)

*Hình 3.1. Trang web chứa danh sách mã BIOS và link tải công cụ*

![Forensic Evidence Figure 11](assets/fig_11.png)

*Hình 3.2. Giải nén file pwgen-5dec.zip*

![Forensic Evidence Figure 12](assets/fig_12.png)

*Hình 3.3. Mở file thực thi pwgen-5dec.exe từ thư mục đã giải nén*

**d) Kết quả & diễn giải:** Công cụ keygen đã được tải về và khởi chạy thành công, giao diện dòng lệnh hiển thị sẵn sàng để nhận mã code đầu vào từ bước 2

### Bước 4. Tạo mật khẩu vượt qua BIOS và lưu ảnh minh chứng

**a) Mô tả thao tác:** Tại cửa sổ Command Prompt của keygen, nhập mã code từ Bước 2 và nhấn Enter. Phần mềm chạy quá trình brute force và trả về danh sách mật khẩu cho từng dòng máy. Ghi nhận mật khẩu ở dòng Generic Phoenix BIOS (ví dụ: khxs). Nhấn Ctrl + Alt để nhả phím khỏi máy ảo, nhấn PrntScrn để chụp màn hình. Mở Paint, dán ảnh và lưu với tên Lab-Proj 8b from ThanhNP.

**b) Câu lệnh / cấu hình đã sử dụng :** Không có

**c) Ảnh minh chứng:**

![Forensic Evidence Figure 13](assets/fig_13.png)

*Hình 4.1. Kết quả tạo mật khẩu từ keygen với mã 11805*

![Forensic Evidence Figure 14](assets/fig_14.png)

*Hình 4.2. Lưu ảnh chụp màn hình kết quả tạo mật khẩu từ keygen*

**d) Kết quả & diễn giải:** Keygen đã tính toán thành công mật khẩu chủ (khxs) từ mã lỗi 11805. Ảnh minh chứng được lưu thành công với định dạng PNG. Lưu ý mỗi lần chạy lại keygen có thể sinh ra mật khẩu khác nhau, cần thử nghiệm thực tế để chọn mật khẩu hoạt động

### Bước 5. Đăng nhập vào BIOS bằng mật khẩu vừa tạo

**a) Mô tả thao tác:** Nhấn Ctrl + Alt để nhả phím khỏi máy ảo. Trên thanh menu của VMware, chọn VM > Power > Power Off. Sau đó chọn VM > Power > Power On to BIOS. Khi hộp thoại Enter Password hiện ra, nhập mật khẩu vừa tìm được từ keygen (ví dụ: khxs) và nhấn Enter. Nếu thành công, giao diện PhoenixBIOS Setup Utility sẽ hiện ra.

**b) Câu lệnh / cấu hình đã sử dụng :** Không có

**c) Ảnh minh chứng:**

![Forensic Evidence Figure 15](assets/fig_15.png)

*Hình 5.1. Tắt máy ảo từ màn hình System Disabled để chuẩn bị khởi động lại vào BIOS*

![Forensic Evidence Figure 16](assets/fig_16.png)

*Hình 5.2. Khởi động máy ảo vào BIOS*

![Forensic Evidence Figure 17](assets/fig_17.png)

*Hình 5.3. Hộp thoại yêu cầu nhập mật khẩu để vào BIOS*

![Forensic Evidence Figure 18](assets/fig_18.png)

*Hình 5.4. Giao diện BIOS mở khóa thành công bằng mật khẩu từ keygen.*

**d) Kết quả & diễn giải:** Đã vượt qua lớp bảo mật mật khẩu BIOS thành công bằng mật khẩu chủ do keygen tạo ra. Điều này chứng minh rằng cơ chế bảo vệ của BIOS đời cũ có thể bị vô hiệu hóa.

### Bước 6. Thiết lập mật khẩu khởi động (Setting a Boot Password)

**a) Mô tả thao tác:** Trong giao diện BIOS, di chuyển sang tab Security. Dùng phím mũi tên xuống chọn mục Password on boot và nhấn Enter. Một hộp thoại nhỏ hiện ra, chọn Enabled và nhấn Enter. Màn hình hiển thị trạng thái Password on boot là Enabled. Nhấn F10 và sau đó nhấn Enter để lưu thay đổi và thoát.

**b) Câu lệnh / cấu hình đã sử dụng :** Không có

**c) Ảnh minh chứng:**

![Forensic Evidence Figure 19](assets/fig_19.png)

*Hình 6.1. Chọn Enabled cho mục Password on boot*

![Forensic Evidence Figure 20](assets/fig_20.png)

*Hình 6.2. Trạng thái Password on boot hiển thị Enabled*

![Forensic Evidence Figure 21](assets/fig_21.png)

*Hình 6.3. Hộp thoại xác nhận lưu thay đổi khi nhấn F10*

**d) Kết quả & diễn giải:** Hệ thống đã được thiết lập để yêu cầu nhập mật khẩu mỗi khi khởi động máy ảo, ngăn chặn việc truy cập vào hệ điều hành nếu không có mật khẩu hợp lệ.

### Bước 7. Kiểm tra giới hạn của Keygen với Boot Password

**a) Mô tả thao tác:** Khởi động lại máy ảo, tại hộp thoại Enter Password, nhập sai 3 lần. Hệ thống hiện màn hình System Disabled với mã code 00000. Nhấn Ctrl + Alt để nhả phím, chụp ảnh màn hình và lưu với tên Lab-Proj 8c from ThanhNP. Chạy lại keygen với mã 00000, nhận mật khẩu mới nhưng khi nhập vào BIOS thì không hoạt động.

**b) Câu lệnh / cấu hình đã sử dụng :** Không có

**c) Ảnh minh chứng:**

![Forensic Evidence Figure 22](assets/fig_22.png)

*Hình 7.1.  Hộp thoại yêu cầu nhập mật khẩu khởi động (Boot Password)*

![Forensic Evidence Figure 23](assets/fig_23.png)

*Hình 7.2.  Cảnh báo nhập sai mật khẩu khởi động*

![Forensic Evidence Figure 24](assets/fig_24.png)

*Hình 7.3.  Màn hình System Disabled với mã 00000*

![Forensic Evidence Figure 25](assets/fig_25.png)

*Hình 7.4.  Lưu ảnh chụp màn hình System Disabled mã 00000 thành file Lab-Proj 8c from ThanhNP*

![Forensic Evidence Figure 26](assets/fig_26.png)

*Hình 7.5.  Kết quả chạy keygen với mã 00000*

**d) Kết quả & diễn giải:** Keygen không thể vượt qua Boot Password. Điều này cho thấy công cụ này chỉ có tác dụng với mật khẩu BIOS (Supervisor Password) chứ không hỗ trợ mật khẩu khởi động.

### Bước 8. Kiểm tra giới hạn của Keygen với Boot Password

**a) Mô tả thao tác:** Khởi động lại máy ảo vào BIOS, nhập mật khẩu gốc 12345678 để truy cập. Chuyển mục Password on boot về Disabled. Chọn Set Supervisor Password, nhập mật khẩu hiện tại 12345678 và nhấn Enter 4 lần để xóa mật khẩu. Màn hình hiển thị cả hai mật khẩu là Clear. Nhấn F10 và Enter để lưu và thoát.

**b) Câu lệnh / cấu hình đã sử dụng :** Không có

**c) Ảnh minh chứng:**

![Forensic Evidence Figure 27](assets/fig_27.png)

*Hình 8.1. Tắt máy ảo từ màn hình System Disabled để chuẩn bị khởi động lại vào BIOS*

![Forensic Evidence Figure 28](assets/fig_28.png)

*Hình 8.2. Khởi động máy ảo vào BIOS*

![Forensic Evidence Figure 29](assets/fig_29.png)

*Hình 8.3. Nhập mật khẩu từ keygen (không thành công với Boot Password)*

![Forensic Evidence Figure 30](assets/fig_30.png)

*Hình 8.4. Tắt máy ảo sau khi thử nghiệm mật khẩu từ keygen không thành công*

![Forensic Evidence Figure 31](assets/fig_31.png)

*Hình 8.5. Khởi động máy ảo vào BIOS để bắt đầu quá trình xóa mật khẩu*

![Forensic Evidence Figure 32](assets/fig_32.png)

*Hình 8.6. Hộp thoại yêu cầu nhập mật khẩu gốc để vào BIOS*

![Forensic Evidence Figure 33](assets/fig_33.png)

*Hình 8.7. Tắt tính năng Password on boot (chuyển về Disabled)*

![Forensic Evidence Figure 34](assets/fig_34.png)

*Hình 8.7. Trạng thái Password on boot đã chuyển sang Disabled*

![Forensic Evidence Figure 35](assets/fig_35.png)

*Hình 8.8. Hộp thoại xóa mật khẩu Supervisor (nhập mật khẩu hiện tại và để trống mật khẩu mới)*

![Forensic Evidence Figure 36](assets/fig_36.png)

*Hình 8.9. Nhập mật khẩu hiện tại để tiến hành xóa mật khẩu Supervisor*

![Forensic Evidence Figure 37](assets/fig_37.png)

*Hình 8.10. Thông báo xác nhận mật khẩu đã được xóa thành công*

![Forensic Evidence Figure 38](assets/fig_38.png)

*Hình 8.11. Giao diện BIOS sau khi xóa mật khẩu thành công (trạng thái Clear)*

![Forensic Evidence Figure 39](assets/fig_39.png)

*Hình 8.12. Hộp thoại xác nhận lưu thay đổi và thoát khỏi BIOS*

**d) Kết quả & diễn giải:** Quá trình điều tra đã khôi phục thành công trạng thái ban đầu của BIOS bằng cách xóa mật khẩu bằng mật khẩu gốc, đảm bảo máy ảo có thể khởi động bình thường trở lại mà không bị giới hạn bởi mật khẩu.

## 3. Tổng hợp Kết quả Điều tra (Forensic Findings)

### 3.1. Bảng tổng hợp kết quả điều tra (Forensic Findings Summary)

## 5. Kết luận, Xử lý Sự cố & Bài học Kinh nghiệm (Conclusions & Lessons Learned)

### 5.1. Kết luận Điều tra

Đã thực hiện thành công quy trình thiết lập và bypass mật khẩu BIOS trên máy ảo VMware. Kết quả kiểm thử cho thấy sự khác biệt rõ rệt giữa hai lớp bảo mật:

Đối với Supervisor Password: Quá trình điều tra đã bypass thành công. Bằng cách nhập sai mật khẩu 3 lần, lấy mã lỗi 11805 và sử dụng Keygen (pwgen-5dec), quá trình điều tra đã tạo ra mật khẩu chủ khxs và truy cập thành công vào BIOS. Điều này chứng minh lỗ hổng bảo mật của BIOS đời cũ, nơi thuật toán tạo mã lỗi bị reverse-engineer.

Đối với Password on boot: Quá trình điều tra đã thất bại khi sử dụng Keygen. Khi bật Password on boot và nhập sai 3 lần, hệ thống hiển thị mã lỗi 00000. Mặc dù Keygen có sinh ra mật khẩu, nhưng không thể vượt qua màn hình khởi động. Điều này cho thấy cơ chế bảo vệ Boot Password (trong môi trường VMware giả lập) là chặt chẽ hơn và không thể bị vượt qua bởi các công cụ Keygen thông thường dành cho BIOS Setup.

Cuối cùng, quá trình điều tra đã khôi phục lại trạng thái ban đầu bằng cách sử dụng mật khẩu gốc 12345678, đưa BIOS về trạng thái Clear. Bài lab đã giúp điều tra viên hiểu rõ tầm quan trọng của việc bảo vệ vật lý thiết bị, vì bất kỳ ai có quyền truy cập vật lý đều có thể vô hiệu hoá lớp bảo vệ BIOS bằng các công cụ có sẵn.

### 5.2. Nhật ký Xử lý Sự cố Kỹ thuật (Troubleshooting Log)

| STT | Khó khăn / lỗi gặp phải | Giải pháp xử lý kỹ thuật |
| --- | --- | --- |
| 1 | Máy ảo khởi động quá nhanh, không kịp bấm phím vào BIOS. | Đã sử dụng tính năng VM > Power > Power On to BIOS của VMware hoặc sửa file .vmx thêm dòng bios.bootdelay = 5000. |
| 2 | Nhập mã lỗi 11805 vào Keygen nhưng mỗi lần chạy lại ra một mật khẩu khác nhau. | Do thuật toán Keygen có tính ngẫu nhiên (brute-force). Quá trình điều tra đã kiểm tra chéo kết quả giữa các lần chạy để chọn ra mật khẩu khxs hoạt động chính xác. |
| 3 | Keygen sinh ra mật khẩu cho mã 00000 nhưng nhập vào không thành công. | Nhận định đây là giới hạn của công cụ (không hỗ trợ Boot Password), quá trình điều tra đã khắc phục bằng cách tắt máy ảo (Power Off) và khởi động lại bằng mật khẩu gốc 12345678 để xoá cấu hình. |

### 5.3. Bài học Rút ra (Key Takeaways)

Kiến thức: Hiểu rõ cơ chế bảo mật của BIOS (Supervisor Password và Password on boot) và nguyên lý lợi dụng mã lỗi System Disabled để tạo mật khẩu chủ trên các dòng BIOS đời cũ.

Kỹ năng: Thành thạo thao tác trên VMware, sử dụng công cụ keygen dòng lệnh và kỹ năng chụp ảnh, lưu trữ minh chứng phục vụ báo cáo.

Liên hệ thực tế: Trong điều tra số, việc vượt qua mật khẩu BIOS là bước quan trọng để truy cập dữ liệu từ thiết bị bị khóa. Tuy nhiên, điều tra viên cần tuân thủ nghiêm ngặt quy định pháp lý và đạo đức nghề nghiệp khi thực hiện các thao tác này.

## 6. Tài liệu Tham khảo (References)

[1] Tài liệu hướng dẫn thực hành Lab 8: Bypassing a BIOS Password, môn FRS301, Trường Đại học FPT.
[2] Dogbert, "Table of reverse-engineered BIOS", Blogspot. [Online]. Available: https://dogber1.blogspot.com/2009/05/table-of-reverse-engineered-bios.html
[3] How-To Geek, "How to Increase the VMware Boot Screen Delay". [Online]. Available: http://www.howtogeek.com/howto/16876/how-to-increase-the-vmware-boot-screen-delay/
