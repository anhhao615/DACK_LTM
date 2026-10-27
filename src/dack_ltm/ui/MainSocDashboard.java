package dack_ltm.ui;

import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;

import dack_ltm.config.SystemConfig;
import dack_ltm.database.JsonDataStore;
import dack_ltm.models.*;
import dack_ltm.security.AclEngine;
import dack_ltm.storage.SecureFileService;

public class MainSocDashboard extends JFrame {
    private User currentUser;
    private String currentPath = "/";

    // Header labels
    private JLabel lblUser;
    private JLabel lblRole;
    private JLabel lblCurrentPath;

    // File Explorer Components
    private JTable tblFiles;
    private DefaultTableModel modelFiles;

    // Audit Log Components
    private JTable tblLogs;
    private DefaultTableModel modelLogs;
    private JComboBox<String> cbLogFilter;

    // Firewall Components
    private JTable tblFirewall;
    private DefaultTableModel modelFirewall;

    // Quarantine Components
    private JTable tblQuarantine;
    private DefaultTableModel modelQuarantine;

    // ACL Matrix Components
    private JTable tblAcl;
    private DefaultTableModel modelAcl;

    public MainSocDashboard() {
        // Mặc định đăng nhập với tài khoản Admin
        this.currentUser = JsonDataStore.getInstance().getUserByUsername("admin");

        setTitle("HỆ THỐNG QUẢN LÝ TRUY CẬP TỆP TIN TỪ XA VỚI XÁC THỰC VÀ ỦY QUYỀN (AUTHORIZATION)");
        setSize(1150, 720);
        setMinimumSize(new Dimension(950, 600));
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        initUI();
        refreshAll();

        // Tự động làm mới log ngầm mỗi 3 giây
        Timer timer = new Timer(3000, e -> refreshLogs());
        timer.start();
    }

    private void initUI() {
        setLayout(new BorderLayout());

        // =====================================================================
        // 1. THANH TIÊU ĐỀ & CHỈ SỐ BẢO MẬT PHÒNG THỦ CHIỀU SÂU
        // =====================================================================
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.setBackground(new Color(15, 23, 42)); // Slate Đậm
        topPanel.setBorder(new EmptyBorder(10, 15, 10, 15));

        // Nhãn nhận diện hệ thống
        JPanel brandPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        brandPanel.setOpaque(false);
        JLabel title = new JLabel("HỆ THỐNG TỆP BẢO MẬT");
        title.setFont(new Font("Segoe UI", Font.BOLD, 17));
        title.setForeground(Color.WHITE);

        JLabel subTitle = new JLabel("[Phòng Thủ Chiều Sâu v2.6]");
        subTitle.setFont(new Font("Segoe UI", Font.BOLD, 12));
        subTitle.setForeground(new Color(56, 189, 248)); // Xanh da trời

        brandPanel.add(title);
        brandPanel.add(subTitle);

        // Chỉ số trạng thái 3 lớp bảo mật
        JPanel defensePanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 8, 0));
        defensePanel.setOpaque(false);
        defensePanel.add(createPill("Proxy Gateway: HOẠT ĐỘNG", new Color(16, 185, 129)));
        defensePanel.add(createPill("Firewall: HOẠT ĐỘNG", new Color(16, 185, 129)));
        defensePanel.add(createPill("Antivirus: HOẠT ĐỘNG", new Color(16, 185, 129)));

        // Thông tin người dùng & Nút mở Web Dashboard
        JPanel userPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        userPanel.setOpaque(false);

        lblUser = new JLabel("Người dùng: admin");
        lblUser.setForeground(Color.WHITE);
        lblUser.setFont(new Font("Segoe UI", Font.BOLD, 12));

        lblRole = new JLabel("[QUẢN TRỊ VIÊN]");
        lblRole.setForeground(new Color(245, 158, 11)); // Màu vàng hổ phách
        lblRole.setFont(new Font("Segoe UI", Font.BOLD, 12));

        JButton btnOpenWeb = new JButton("🌐 Mở Web Dashboard (Trình duyệt)");
        btnOpenWeb.setBackground(new Color(37, 99, 235));
        btnOpenWeb.setForeground(Color.WHITE);
        btnOpenWeb.setFocusPainted(false);
        btnOpenWeb.addActionListener(e -> openWebBrowser());

        userPanel.add(lblUser);
        userPanel.add(lblRole);
        userPanel.add(btnOpenWeb);

        topPanel.add(brandPanel, BorderLayout.WEST);
        topPanel.add(defensePanel, BorderLayout.CENTER);
        topPanel.add(userPanel, BorderLayout.EAST);

        // =====================================================================
        // 2. THANH CHUYỂN NHANH VAI TRÒ DEMO (QUICK SWITCHER)
        // =====================================================================
        JPanel switchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        switchPanel.setBackground(new Color(30, 41, 59));
        JLabel lblQuick = new JLabel("⚡ Chuyển nhanh vai trò Demo:");
        lblQuick.setForeground(new Color(148, 163, 184));
        lblQuick.setFont(new Font("Segoe UI", Font.BOLD, 11));
        switchPanel.add(lblQuick);

        JButton btnAdmin = createQuickBtn("admin (Quản trị: Toàn quyền)", "admin");
        JButton btnAlice = createQuickBtn("user (Kỹ sư: Đọc/Ghi @ /projects, Đọc @ /policies)", "user");
        JButton btnBob = createQuickBtn("guest (Khách: Chỉ Đọc, Không được Ghi)", "guest");

        switchPanel.add(btnAdmin);
        switchPanel.add(btnAlice);
        switchPanel.add(btnBob);

        JPanel northContainer = new JPanel(new BorderLayout());
        northContainer.add(topPanel, BorderLayout.NORTH);
        northContainer.add(switchPanel, BorderLayout.SOUTH);
        add(northContainer, BorderLayout.NORTH);

        // =====================================================================
        // 3. THANH ĐIỀU HƯỚNG TAB
        // =====================================================================
        JTabbedPane tabs = new JTabbedPane();
        tabs.setFont(new Font("Segoe UI", Font.BOLD, 13));

        tabs.addTab("📁 Quản lý Tệp tin Từ xa", createFilesPanel());
        tabs.addTab("🛡️ Nhật ký Kiểm toán SOC", createLogsPanel());
        tabs.addTab("🔥 Cấu hình Firewall", createFirewallPanel());
        tabs.addTab("🦠 Antivirus & Khu cách ly", createAntivirusPanel());
        tabs.addTab("🔑 Ma trận Phân quyền ACL", createAclPanel());

        add(tabs, BorderLayout.CENTER);
    }

    private JLabel createPill(String text, Color col) {
        JLabel l = new JLabel(" ● " + text + " ");
        l.setFont(new Font("Segoe UI", Font.BOLD, 11));
        l.setForeground(col);
        l.setOpaque(true);
        l.setBackground(new Color(15, 23, 42));
        l.setBorder(BorderFactory.createLineBorder(col, 1));
        return l;
    }

    private JButton createQuickBtn(String title, String username) {
        JButton b = new JButton(title);
        b.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        b.setBackground(new Color(51, 65, 85));
        b.setForeground(Color.WHITE);
        b.setFocusPainted(false);
        b.addActionListener(e -> {
            User u = JsonDataStore.getInstance().getUserByUsername(username);
            if (u != null) {
                this.currentUser = u;
                lblUser.setText("Người dùng: " + u.getUsername());
                String roleVN = "ADMIN".equals(u.getRole()) ? "[QUẢN TRỊ VIÊN]" : ("USER".equals(u.getRole()) ? "[KỸ SƯ AN NINH]" : "[THỰC TẬP SINH]");
                lblRole.setText(roleVN);
                refreshFiles();
                JOptionPane.showMessageDialog(this, 
                    "Đã chuyển đổi ngữ cảnh sang tài khoản: " + u.getUsername() + " (" + roleVN + ")\nHọ tên: " + u.getFullName(),
                    "Chuyển đổi Tài khoản Thành công", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        return b;
    }

    // =========================================================================
    // TAB 1: TRÌNH QUẢN LÝ TỆP TIN TỪ XA
    // =========================================================================
    private JPanel createFilesPanel() {
        JPanel p = new JPanel(new BorderLayout(5, 5));
        p.setBorder(new EmptyBorder(10, 10, 10, 10));

        // Thanh công cụ thao tác
        JPanel tb = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 5));
        JButton btnUp = new JButton("⬆ Lên thư mục cha");
        JButton btnRefresh = new JButton("🔄 Làm mới");
        JButton btnRead = new JButton("👁 Xem nội dung");
        JButton btnEdit = new JButton("✏ Sửa tệp");
        JButton btnNewFile = new JButton("➕ Tệp mới");
        JButton btnUpload = new JButton("☁ Tải lên");
        JButton btnMkdir = new JButton("📁 Thư mục mới");
        JButton btnDelete = new JButton("🗑 Xóa");

        lblCurrentPath = new JLabel("Đường dẫn hiện tại: " + currentPath);
        lblCurrentPath.setFont(new Font("Segoe UI", Font.BOLD, 12));

        btnUp.addActionListener(e -> navigateUp());
        btnRefresh.addActionListener(e -> refreshFiles());
        btnRead.addActionListener(e -> readSelectedFile());
        btnEdit.addActionListener(e -> editSelectedFile());
        btnNewFile.addActionListener(e -> createNewFileDialog());
        btnUpload.addActionListener(e -> uploadFileDialog());
        btnMkdir.addActionListener(e -> createNewFolderDialog());
        btnDelete.addActionListener(e -> deleteSelectedResource());

        tb.add(btnUp);
        tb.add(btnRefresh);
        tb.add(new JSeparator(JSeparator.VERTICAL));
        tb.add(btnRead);
        tb.add(btnEdit);
        tb.add(btnNewFile);
        tb.add(btnUpload);
        tb.add(btnMkdir);
        tb.add(btnDelete);
        tb.add(new JSeparator(JSeparator.VERTICAL));
        tb.add(lblCurrentPath);

        p.add(tb, BorderLayout.NORTH);

        // Bảng danh sách tệp
        String[] cols = { "Loại", "Tên tệp / thư mục", "Huy hiệu Quyền hạn ACL", "Kích thước", "Thời gian sửa đổi" };
        modelFiles = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        tblFiles = new JTable(modelFiles);
        tblFiles.setRowHeight(26);
        tblFiles.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        tblFiles.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 12));

        // Định dạng màu sắc cho huy hiệu quyền
        tblFiles.getColumnModel().getColumn(2).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                String val = value != null ? value.toString() : "";
                if (val.contains("Ghi") || val.contains("Quản trị")) {
                    c.setForeground(new Color(22, 163, 74)); // Xanh lá
                } else if (val.contains("Đọc")) {
                    c.setForeground(new Color(202, 138, 4)); // Vàng hổ phách
                } else {
                    c.setForeground(new Color(220, 38, 38)); // Đỏ
                }
                return c;
            }
        });

        // Nhấp đúp chuột để mở thư mục hoặc xem tệp
        tblFiles.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && tblFiles.getSelectedRow() != -1) {
                    int r = tblFiles.getSelectedRow();
                    String type = (String) modelFiles.getValueAt(r, 0);
                    String name = (String) modelFiles.getValueAt(r, 1);
                    if ("THƯ MỤC".equals(type)) {
                        currentPath = currentPath.equals("/") ? "/" + name : currentPath + "/" + name;
                        refreshFiles();
                    } else {
                        readSelectedFile();
                    }
                }
            }
        });

        p.add(new JScrollPane(tblFiles), BorderLayout.CENTER);
        return p;
    }

    private void navigateUp() {
        if (!currentPath.equals("/")) {
            int lastSlash = currentPath.lastIndexOf('/');
            currentPath = (lastSlash <= 0) ? "/" : currentPath.substring(0, lastSlash);
            refreshFiles();
        }
    }

    private void refreshFiles() {
        lblCurrentPath.setText("Đường dẫn hiện tại: " + currentPath);
        modelFiles.setRowCount(0);

        SecureFileService.OpResult<List<SecureFileService.FileItem>> res = 
            SecureFileService.listDirectory(currentUser, currentPath);

        if (!res.success) {
            JOptionPane.showMessageDialog(this, res.message, "Truy cập bị từ chối (AuthZ)", JOptionPane.WARNING_MESSAGE);
            navigateUp();
            return;
        }

        for (SecureFileService.FileItem it : res.data) {
            modelFiles.addRow(new Object[] {
                it.isDir ? "THƯ MỤC" : "TỆP TIN",
                it.name,
                it.badge,
                it.isDir ? "-" : it.size + " B",
                it.modifiedAt
            });
        }
    }

    private void readSelectedFile() {
        int r = tblFiles.getSelectedRow();
        if (r == -1) {
            JOptionPane.showMessageDialog(this, "Vui lòng chọn một tệp tin để xem.", "Thông báo", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String type = (String) modelFiles.getValueAt(r, 0);
        String name = (String) modelFiles.getValueAt(r, 1);
        if ("THƯ MỤC".equals(type)) {
            JOptionPane.showMessageDialog(this, "Mục đã chọn là thư mục, không phải tệp tin văn bản.", "Thông báo", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String target = currentPath.equals("/") ? "/" + name : currentPath + "/" + name;
        SecureFileService.OpResult<SecureFileService.FileViewData> res = SecureFileService.readFile(currentUser, target);

        if (!res.success) {
            JOptionPane.showMessageDialog(this, res.message, "Thao tác Đọc bị chặn (AuthZ)", JOptionPane.ERROR_MESSAGE);
            return;
        }

        JTextArea ta = new JTextArea(res.data != null ? res.data.content : "", 20, 60);
        ta.setFont(new Font("Consolas", Font.PLAIN, 12));
        ta.setEditable(false);
        JOptionPane.showMessageDialog(this, new JScrollPane(ta), "Nội dung tệp tin: " + target, JOptionPane.PLAIN_MESSAGE);
    }

    private void editSelectedFile() {
        int r = tblFiles.getSelectedRow();
        if (r == -1) {
            JOptionPane.showMessageDialog(this, "Vui lòng chọn một tệp tin để chỉnh sửa.", "Thông báo", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String type = (String) modelFiles.getValueAt(r, 0);
        String name = (String) modelFiles.getValueAt(r, 1);
        if ("THƯ MỤC".equals(type)) {
            JOptionPane.showMessageDialog(this, "Không thể chỉnh sửa thư mục.", "Thông báo", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String target = currentPath.equals("/") ? "/" + name : currentPath + "/" + name;
        SecureFileService.OpResult<SecureFileService.FileViewData> readRes = SecureFileService.readFile(currentUser, target);
        if (!readRes.success) {
            JOptionPane.showMessageDialog(this, readRes.message, "Chỉnh sửa bị chặn (AuthZ)", JOptionPane.ERROR_MESSAGE);
            return;
        }

        JTextArea ta = new JTextArea(readRes.data != null ? readRes.data.content : "", 20, 60);
        ta.setFont(new Font("Consolas", Font.PLAIN, 12));
        int opt = JOptionPane.showConfirmDialog(this, new JScrollPane(ta), "Chỉnh sửa tệp: " + target, JOptionPane.OK_CANCEL_OPTION);
        if (opt == JOptionPane.OK_OPTION) {
            byte[] newBytes = ta.getText().getBytes(StandardCharsets.UTF_8);
            SecureFileService.OpResult<String> writeRes = SecureFileService.writeFile(
                currentUser, target, newBytes, "127.0.0.1", "GUI-EDIT"
            );
            if (!writeRes.success) {
                JOptionPane.showMessageDialog(this, writeRes.message, "Thao tác Ghi bị chặn (Antivirus / AuthZ)", JOptionPane.ERROR_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, "Lưu tệp tin thành công!", "Thành công", JOptionPane.INFORMATION_MESSAGE);
                refreshFiles();
            }
        }
    }

    private void createNewFileDialog() {
        String filename = JOptionPane.showInputDialog(this, "Nhập tên tệp tin mới (ví dụ: notes.txt):");
        if (filename == null || filename.trim().isEmpty()) return;

        JTextArea ta = new JTextArea(10, 40);
        int opt = JOptionPane.showConfirmDialog(this, new JScrollPane(ta), "Nhập nội dung khởi tạo cho: " + filename, JOptionPane.OK_CANCEL_OPTION);
        if (opt == JOptionPane.OK_OPTION) {
            String target = currentPath.equals("/") ? "/" + filename : currentPath + "/" + filename;
            SecureFileService.OpResult<String> res = SecureFileService.writeFile(
                currentUser, target, ta.getText().getBytes(StandardCharsets.UTF_8), "127.0.0.1", "GUI-NEWFILE"
            );
            if (!res.success) {
                JOptionPane.showMessageDialog(this, res.message, "Tạo tệp bị chặn (Antivirus / AuthZ)", JOptionPane.ERROR_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, "Tạo tệp tin thành công!", "Thành công", JOptionPane.INFORMATION_MESSAGE);
                refreshFiles();
            }
        }
    }

    private void uploadFileDialog() {
        JFileChooser fc = new JFileChooser();
        int opt = fc.showOpenDialog(this);
        if (opt == JFileChooser.APPROVE_OPTION) {
            File selected = fc.getSelectedFile();
            try {
                byte[] content = java.nio.file.Files.readAllBytes(selected.toPath());
                String target = currentPath.equals("/") ? "/" + selected.getName() : currentPath + "/" + selected.getName();
                SecureFileService.OpResult<String> res = SecureFileService.writeFile(
                    currentUser, target, content, "127.0.0.1", "GUI-UPLOAD"
                );
                if (!res.success) {
                    JOptionPane.showMessageDialog(this, res.message, "Tải lên bị chặn (Antivirus / AuthZ)", JOptionPane.ERROR_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(this, "Tải tệp tin lên thành công!", "Thành công", JOptionPane.INFORMATION_MESSAGE);
                    refreshFiles();
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Lỗi đọc tệp tin cục bộ: " + ex.getMessage(), "Lỗi", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void createNewFolderDialog() {
        String dirName = JOptionPane.showInputDialog(this, "Nhập tên thư mục mới cần tạo:");
        if (dirName == null || dirName.trim().isEmpty()) return;

        String target = currentPath.equals("/") ? "/" + dirName : currentPath + "/" + dirName;
        SecureFileService.OpResult<String> res = SecureFileService.createDirectory(currentUser, target, "127.0.0.1", "GUI-MKDIR");
        if (!res.success) {
            JOptionPane.showMessageDialog(this, res.message, "Tạo thư mục bị chặn (AuthZ)", JOptionPane.ERROR_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this, "Tạo thư mục thành công!", "Thành công", JOptionPane.INFORMATION_MESSAGE);
            refreshFiles();
        }
    }

    private void deleteSelectedResource() {
        int r = tblFiles.getSelectedRow();
        if (r == -1) {
            JOptionPane.showMessageDialog(this, "Vui lòng chọn một tài nguyên để xóa.", "Thông báo", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String name = (String) modelFiles.getValueAt(r, 1);
        String target = currentPath.equals("/") ? "/" + name : currentPath + "/" + name;

        int conf = JOptionPane.showConfirmDialog(this, "Bạn có chắc chắn muốn xóa: " + target + "?", "Xác nhận Xóa", JOptionPane.YES_NO_OPTION);
        if (conf == JOptionPane.YES_OPTION) {
            SecureFileService.OpResult<String> res = SecureFileService.deleteResource(currentUser, target, "127.0.0.1", "GUI-DELETE");
            if (!res.success) {
                JOptionPane.showMessageDialog(this, res.message, "Xóa bị chặn (AuthZ)", JOptionPane.ERROR_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, "Đã xóa tài nguyên thành công!", "Thành công", JOptionPane.INFORMATION_MESSAGE);
                refreshFiles();
            }
        }
    }

    // =========================================================================
    // TAB 2: NHẬT KÝ KIỂM TOÁN AN NINH SOC
    // =========================================================================
    private JPanel createLogsPanel() {
        JPanel p = new JPanel(new BorderLayout(5, 5));
        p.setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel tb = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        tb.add(new JLabel("Lọc trạng thái:"));
        cbLogFilter = new JComboBox<>(new String[] {
            "ALL", "ALLOWED", "DENIED_AUTHZ", "BLOCKED_FIREWALL", "BLOCKED_PROXY", "QUARANTINED_AV", "AUTHN_FAILED"
        });
        cbLogFilter.addActionListener(e -> refreshLogs());
        tb.add(cbLogFilter);

        JButton btnRef = new JButton("🔄 Làm mới Nhật ký");
        btnRef.addActionListener(e -> refreshLogs());
        tb.add(btnRef);

        p.add(tb, BorderLayout.NORTH);

        String[] cols = { "Thời gian", "Địa chỉ IP", "Người dùng", "Hành động", "Đường dẫn", "Trạng thái", "Mã HTTP", "Lý do / Ghi chú bảo mật" };
        modelLogs = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        tblLogs = new JTable(modelLogs);
        tblLogs.setRowHeight(24);
        tblLogs.setFont(new Font("Consolas", Font.PLAIN, 11));

        p.add(new JScrollPane(tblLogs), BorderLayout.CENTER);
        return p;
    }

    private void refreshLogs() {
        String filter = (String) cbLogFilter.getSelectedItem();
        List<AuditLog> logs = JsonDataStore.getInstance().getAllAuditLogs(filter);
        modelLogs.setRowCount(0);
        for (AuditLog l : logs) {
            modelLogs.addRow(new Object[] {
                l.getFormattedTime(), l.getClientIp(), l.getUsername(), l.getAction(),
                l.getResourcePath(), l.getStatus(), l.getStatusCode(), l.getReason()
            });
        }
    }

    // =========================================================================
    // TAB 3: CẤU HÌNH FIREWALL
    // =========================================================================
    private JPanel createFirewallPanel() {
        JPanel p = new JPanel(new BorderLayout(5, 5));
        p.setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel tb = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        JButton btnAddIp = new JButton("➕ Thêm IP vào Blacklist");
        JButton btnDelIp = new JButton("🗑 Xóa quy tắc");
        JButton btnRef = new JButton("🔄 Làm mới");

        btnAddIp.addActionListener(e -> {
            String ip = JOptionPane.showInputDialog(this, "Nhập địa chỉ IP cần chặn (ví dụ: 192.168.1.99):");
            if (ip != null && !ip.trim().isEmpty()) {
                String reason = JOptionPane.showInputDialog(this, "Nhập lý do chặn:", "Phát hiện hành vi quét cổng độc hại");
                JsonDataStore.getInstance().addFirewallRule(ip.trim(), "BLACKLIST", reason, null);
                refreshFirewall();
            }
        });

        btnDelIp.addActionListener(e -> {
            int r = tblFirewall.getSelectedRow();
            if (r != -1) {
                int id = (int) modelFirewall.getValueAt(r, 0);
                JsonDataStore.getInstance().deleteFirewallRule(id);
                refreshFirewall();
            }
        });

        btnRef.addActionListener(e -> refreshFirewall());

        tb.add(btnAddIp);
        tb.add(btnDelIp);
        tb.add(btnRef);
        p.add(tb, BorderLayout.NORTH);

        String[] cols = { "Mã quy tắc", "Địa chỉ IP", "Loại quy tắc", "Lý do / Kích hoạt Auto-Lock", "Kích hoạt" };
        modelFirewall = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        tblFirewall = new JTable(modelFirewall);
        tblFirewall.setRowHeight(24);

        p.add(new JScrollPane(tblFirewall), BorderLayout.CENTER);
        return p;
    }

    private void refreshFirewall() {
        modelFirewall.setRowCount(0);
        for (FirewallRule r : JsonDataStore.getInstance().getAllFirewallRules()) {
            modelFirewall.addRow(new Object[] {
                r.getId(), r.getIpAddress(), r.getRuleType(), r.getReason(), r.isActive() ? "HOẠT ĐỘNG" : "TẮT"
            });
        }
    }

    // =========================================================================
    // TAB 4: ANTIVIRUS & KHU VỰC CÁCH LY (QUARANTINE)
    // =========================================================================
    private JPanel createAntivirusPanel() {
        JPanel p = new JPanel(new BorderLayout(5, 5));
        p.setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel tb = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        JButton btnDel = new JButton("🗑 Tiêu hủy tệp mã độc");
        JButton btnRef = new JButton("🔄 Làm mới Khu cách ly");

        btnDel.addActionListener(e -> {
            int r = tblQuarantine.getSelectedRow();
            if (r != -1) {
                String qid = (String) modelQuarantine.getValueAt(r, 0);
                JsonDataStore.getInstance().deleteQuarantineRecord(qid);
                refreshQuarantine();
            }
        });
        btnRef.addActionListener(e -> refreshQuarantine());

        tb.add(btnDel);
        tb.add(btnRef);
        p.add(tb, BorderLayout.NORTH);

        String[] cols = { "Mã cách ly", "Tên tệp gốc", "Tên mã độc phát hiện", "Bước phát hiện", "Kích thước", "Người tải lên", "Thời gian cách ly" };
        modelQuarantine = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        tblQuarantine = new JTable(modelQuarantine);
        tblQuarantine.setRowHeight(24);

        p.add(new JScrollPane(tblQuarantine), BorderLayout.CENTER);
        return p;
    }

    private void refreshQuarantine() {
        modelQuarantine.setRowCount(0);
        for (QuarantineRecord r : JsonDataStore.getInstance().getAllQuarantineRecords()) {
            modelQuarantine.addRow(new Object[] {
                r.getId(), r.getOriginalFilename(), r.getThreatName(), r.getDetectedByStep(),
                r.getFileSize() + " B", r.getUploaderUsername() + "@" + r.getUploaderIp(), r.getFormattedTime()
            });
        }
    }

    // =========================================================================
    // TAB 5: MA TRẬN PHÂN QUYỀN ACL
    // =========================================================================
    private JPanel createAclPanel() {
        JPanel p = new JPanel(new BorderLayout(5, 5));
        p.setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel tb = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        JButton btnAdd = new JButton("➕ Cấu hình quyền ACL");
        JButton btnDel = new JButton("🗑 Xóa quy tắc");
        JButton btnRef = new JButton("🔄 Làm mới Ma trận");

        btnAdd.addActionListener(e -> showAddAclDialog());
        btnDel.addActionListener(e -> {
            int r = tblAcl.getSelectedRow();
            if (r != -1) {
                int id = (int) modelAcl.getValueAt(r, 0);
                JsonDataStore.getInstance().deletePermission(id);
                refreshAcl();
            }
        });
        btnRef.addActionListener(e -> refreshAcl());

        tb.add(btnAdd);
        tb.add(btnDel);
        tb.add(btnRef);
        p.add(tb, BorderLayout.NORTH);

        String[] cols = { "Mã quy tắc", "Đường dẫn tài nguyên", "Đối tượng (User / Role)", "Quyền Đọc", "Quyền Ghi", "Quyền Xóa", "Cấm tuyệt đối (Deny)" };
        modelAcl = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        tblAcl = new JTable(modelAcl);
        tblAcl.setRowHeight(24);

        p.add(new JScrollPane(tblAcl), BorderLayout.CENTER);
        return p;
    }

    private void showAddAclDialog() {
        JTextField tfPath = new JTextField("/projects", 20);
        JComboBox<String> cbUser = new JComboBox<>(new String[] { "user", "guest", "admin", "-- Không chọn (Áp dụng theo Role) --" });
        JComboBox<String> cbRole = new JComboBox<>(new String[] { "-- Không chọn --", "USER", "GUEST", "ADMIN" });
        JCheckBox chkR = new JCheckBox("Quyền Đọc", true);
        JCheckBox chkW = new JCheckBox("Quyền Ghi", false);
        JCheckBox chkD = new JCheckBox("Quyền Xóa", false);
        JCheckBox chkDeny = new JCheckBox("Cấm tuyệt đối (Explicit Deny)", false);

        JPanel form = new JPanel(new GridLayout(7, 2, 5, 5));
        form.add(new JLabel("Đường dẫn tài nguyên:")); form.add(tfPath);
        form.add(new JLabel("Người dùng (User):")); form.add(cbUser);
        form.add(new JLabel("Vai trò (Role):")); form.add(cbRole);
        form.add(chkR); form.add(chkW);
        form.add(chkD); form.add(chkDeny);

        int opt = JOptionPane.showConfirmDialog(this, form, "Cấu hình Quy tắc Phân quyền ACL", JOptionPane.OK_CANCEL_OPTION);
        if (opt == JOptionPane.OK_OPTION) {
            String path = tfPath.getText().trim();
            Integer uid = null;
            String selUser = (String) cbUser.getSelectedItem();
            if (selUser != null && !selUser.startsWith("--")) {
                User u = JsonDataStore.getInstance().getUserByUsername(selUser);
                if (u != null) uid = u.getId();
            }
            String selRole = (String) cbRole.getSelectedItem();
            if (selRole != null && selRole.startsWith("--")) selRole = null;

            JsonDataStore.getInstance().addPermission(
                path, uid, selRole, chkR.isSelected(), chkW.isSelected(), chkD.isSelected(), chkDeny.isSelected()
            );
            refreshAcl();
        }
    }

    private void refreshAcl() {
        modelAcl.setRowCount(0);
        for (FilePermission p : JsonDataStore.getInstance().getAllPermissions()) {
            String subject = "-";
            if (p.getUserId() != null) {
                User u = JsonDataStore.getInstance().getUserById(p.getUserId());
                subject = "User: " + (u != null ? u.getUsername() : p.getUserId());
            } else if (p.getRole() != null) {
                subject = "Role: " + p.getRole();
            }
            modelAcl.addRow(new Object[] {
                p.getId(), p.getResourcePath(), subject,
                p.isCanRead() ? "CÓ" : "KHÔNG",
                p.isCanWrite() ? "CÓ" : "KHÔNG",
                p.isCanDelete() ? "CÓ" : "KHÔNG",
                p.isDeny() ? "CẤM (DENY)" : "CHO PHÉP"
            });
        }
    }

    private void refreshAll() {
        refreshFiles();
        refreshLogs();
        refreshFirewall();
        refreshQuarantine();
        refreshAcl();
    }

    private void openWebBrowser() {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(new URI("http://localhost:" + SystemConfig.HTTP_PORT + "/"));
            } else {
                JOptionPane.showMessageDialog(this, "Vui lòng mở trình duyệt và truy cập: http://localhost:" + SystemConfig.HTTP_PORT + "/");
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Không thể mở trình duyệt tự động: " + ex.getMessage());
        }
    }
}
