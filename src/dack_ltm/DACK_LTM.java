package dack_ltm;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import dack_ltm.config.SystemConfig;
import dack_ltm.database.JsonDataStore;
import dack_ltm.server.EmbeddedHttpServer;
import dack_ltm.ui.MainSocDashboard;

/**
 * Điểm khởi chạy chính của Dự án Apache NetBeans DACK_LTM.
 * Hệ thống Quản lý Truy cập Tệp tin Từ xa với Phòng thủ Chiều sâu (Defense-in-Depth):
 * [Proxy Layer] -> [Firewall Layer] -> [AuthN JWT] -> [AuthZ ACL] -> [Antivirus Scanner] -> [File Storage]
 */
public class DACK_LTM {

    public static void main(String[] args) {
        // 1. Khởi tạo Cơ sở Dữ liệu & Tự động tạo dữ liệu mẫu (Auto-Seeding)
        System.out.println(">>> [1/3] Đang nạp cơ sở dữ liệu và thiết lập mốc bảo mật ban đầu...");
        JsonDataStore ds = JsonDataStore.getInstance();

        // 2. Khởi chạy Cổng Gateway Reverse Proxy & Server HTTP nhúng
        System.out.println(">>> [2/3] Đang khởi chạy Reverse Proxy & Web Gateway trên cổng " + SystemConfig.HTTP_PORT + "...");
        EmbeddedHttpServer server = new EmbeddedHttpServer();
        try {
            server.start(SystemConfig.HTTP_PORT);
        } catch (Exception e) {
            System.err.println("[-] Cảnh báo: Không thể mở cổng HTTP " + SystemConfig.HTTP_PORT + ": " + e.getMessage());
        }

        // In Banner thông tin hướng dẫn ra cửa sổ Output của NetBeans
        String lanIp = SystemConfig.getLanIpAddress();
        String banner = """
========================================================================================
   HỆ THỐNG QUẢN LÝ TRUY CẬP TỆP TIN TỪ XA VỚI XÁC THỰC VÀ ỦY QUYỀN (AUTHORIZATION)
       TÍCH HỢP 3 LỚP BẢO MẬT MẠNG: REVERSE PROXY, FIREWALL VÀ ANTIVIRUS SCANNERS
========================================================================================
 [*] Chuỗi Bảo Mật Phòng Thủ Chiều Sâu (Defense-in-Depth):
     Client -> [1. Proxy Layer] -> [2. Firewall Layer] -> [3. AuthN JWT] 
            -> [4. AuthZ ACL/RBAC] -> [5. Antivirus Scanner] -> [6. File Storage]

 [*] Tài khoản mẫu tự động khởi tạo (Auto-Seeded Accounts):
     +--------------------------------------------------------------------------------+
     | Tài khoản| Mật khẩu   | Vai trò| Quyền hạn chi tiết                            |
     +----------+------------+--------+-----------------------------------------------+
     | admin    | admin123   | ADMIN  | Superadmin: Toàn quyền hệ thống & SOC         |
     | user     | user123    | USER   | Đọc & Ghi tại /projects, Chỉ đọc /policies    |
     |          |            |        | Cấm tuyệt đối (Deny) tại /hr_confidential     |
     | guest    | guest123   | GUEST  | Chỉ Đọc tại /projects và /company_policies    |
     |          |            |        | Cấm tuyệt đối (Deny) tại /hr_confidential     |
     |          |            |        | Không có quyền Ghi ở bất kỳ thư mục nào       |
     +--------------------------------------------------------------------------------+

 [*] Địa chỉ truy cập Web (Hỗ trợ đa thiết bị qua Mạng LAN / Wi-Fi):
     -> Máy này (Local)        : http://localhost:%d/
     -> Thiết bị khác (Mạng LAN): http://%s:%d/ (Mở trên điện thoại, laptop khác cùng Wi-Fi)
     -> Giao diện Java Swing   : Đang hiển thị cửa sổ Cyber SOC Desktop Dashboard...
========================================================================================
""".formatted(SystemConfig.HTTP_PORT, lanIp, SystemConfig.HTTP_PORT);

        System.out.println(banner);

        // 3. Khởi chạy Giao diện Desktop Java Swing
        System.out.println(">>> [3/3] Đang mở giao diện Java Swing Cyber SOC Desktop Dashboard...");
        SwingUtilities.invokeLater(() -> {
            try {
                for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                    if ("Nimbus".equals(info.getName())) {
                        UIManager.setLookAndFeel(info.getClassName());
                        break;
                    }
                }
                new MainSocDashboard().setVisible(true);
            } catch (Throwable ex) {
                System.out.println("[-] Giao diện Swing Desktop: " + ex.getMessage());
            }
        });
    }
}
