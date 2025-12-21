/**
 * @file personalapp.cpp
 * @brief Kişisel finans danışmanı konsol uygulaması.
 */
#include <iostream>
#include <string>
#include <limits>
#include "../header/personalapp.h"
#include "../../personal/header/personal.h"
#include "../../personal/header/database.h"
// 🛡️ VERİ GÜVENLİĞİ: Merkezi güvenlik modülü
#include "../../personal/header/data_security.hpp"
// 🛡️ RASP: Runtime Application Self-Protection modülü
#include "../../personal/header/rasp_protection.hpp"
// 🔐 GÜVENLİ İLETİŞİM: SSL/TLS, Sertifika Pinning, Oturum Anahtarı Yönetimi
#include "../../personal/header/secure_communication.hpp"

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <vector>
#include <conio.h> // _getch() için
#else
#include <unistd.h> // readlink için
#endif

#pragma execution_character_set("utf-8")   // <--- Türkçe karakterler için eklendi.

using namespace Kerem::personal;

namespace {
    // 🛡️ VERİ GÜVENLİĞİ: Şifre girişi için güvenli maskeleme (buffer limit)
    std::string getPasswordMasked() {
#ifdef _WIN32
        const size_t MAX_PASSWORD_LENGTH = 128; // Maksimum şifre uzunluğu
        std::string password;
        password.reserve(MAX_PASSWORD_LENGTH);
        
        char ch;
        while (true) {
            ch = _getch(); // Karakteri ekrana yazdırmadan oku
            if (ch == '\r' || ch == '\n') { // Enter tuşu
                break;
            } else if (ch == '\b') { // Backspace tuşu
                if (!password.empty()) {
                    password.pop_back();
                    std::cout << "\b \b"; // Ekrandan sil
                }
            } else if (ch >= 32 && ch <= 126) { // Yazdırılabilir karakterler
                // 🛡️ VERİ GÜVENLİĞİ: Maksimum uzunluk kontrolü
                if (password.length() >= MAX_PASSWORD_LENGTH) {
                    std::cout << "\a"; // Beep (limit aşıldı)
                    continue;
                }
                password += ch;
                std::cout << '*'; // Yıldız göster
            }
        }
        std::cout << '\n';
        return password;
#else
        // Linux/Mac için basit versiyon (maskeleme yok)
        const size_t MAX_PASSWORD_LENGTH = 128;
        std::string password;
        std::getline(std::cin, password);
        
        // 🛡️ VERİ GÜVENLİĞİ: Maksimum uzunluk kontrolü
        if (password.length() > MAX_PASSWORD_LENGTH) {
            password = password.substr(0, MAX_PASSWORD_LENGTH);
        }
        return password;
#endif
    }

    // --------- Ortak yardımcılar ----------
    void clearCin() {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    void clearScreen() {
#ifdef _WIN32
        system("cls");
#else
        system("clear");
#endif
    }

    void drawLine() { std::cout << "==========================================" << '\n'; }
    void mainMenuVisual(const std::string& username = "") {
        drawLine();
        std::cout << "       Kisisel Finans Danismani\n";
        if (!username.empty()) {
            std::cout << "       Hos geldiniz, " << username << "!\n";
        }
        drawLine();
        std::cout << " 1) Butce planlama ve takip\n";
        std::cout << " 2) Yatirim portfoy yonetimi\n";
        std::cout << " 3) Finansal hedefler\n";
        std::cout << " 4) Borc azaltma stratejileri\n";
        std::cout << " 5) Guvenli Iletisim Demo\n";
        std::cout << " 0) Cikis\n";
        drawLine();
        std::cout << "Seciminiz: ";
    }

    // Güvenli tamsayı okuma
    bool readIntSafe(const char* prompt, int& out) {
        std::cout << prompt;
        if (!(std::cin >> out)) { clearCin(); return false; }
        clearCin(); return true;
    }

    // Login/Register menüsü
    int showAuthMenu(DatabaseManager& db, UserAuth& auth) {
        while (true) {
            clearScreen();
            drawLine();
            std::cout << "       \xF0\x9F\x94\x90 Kullanici Girisi\n";
            drawLine();
            std::cout << " 1) \xF0\x9F\x93\x9D Kayit Ol (Register)\n";
            std::cout << " 2) \xF0\x9F\x94\x91 Giris Yap (Login)\n";
            std::cout << " 0) \xE2\x9D\x8C Cikis\n";
            drawLine();

            int choice;
            if (!readIntSafe("Seciminiz: ", choice)) {
                std::cout << u8"Gecersiz giris!\n";
                continue;
            }

            if (choice == 0) {
                return -1; // Cikis
            }
            else if (choice == 1) {
                // 🛡️ VERİ GÜVENLİĞİ: Güvenli kayıt (input validation)
                clearScreen();
                std::cout << u8"\n=== Kayit Ol ===\n";
                std::string username, email;
                
                std::cout << u8"Kullanici adi (3-32 karakter, alfanumerik): ";
                std::getline(std::cin, username);
                
                // 🛡️ VERİ GÜVENLİĞİ: Username validation (data_security modülü)
                if (!Kerem::DataSecurity::validateInput(username, Kerem::DataSecurity::InputType::USERNAME)) {
                    std::cout << u8"\n⚠ Gecersiz kullanici adi! 3-32 karakter, alfanumerik olmali.\n";
                    std::cout << u8"Devam etmek icin Enter tusuna basin...";
                    std::cin.get();
                    continue;
                }
                
                std::cout << u8"Sifre (min 8 karakter): ";
                std::string password = getPasswordMasked();
                
                // 🛡️ VERİ GÜVENLİĞİ: Password strength check
                if (password.length() < 8) {
                    std::cout << u8"\n⚠ Sifre en az 8 karakter olmalidir!\n";
                    std::cout << u8"Devam etmek icin Enter tusuna basin...";
                    std::cin.get();
                    continue;
                }
                
                std::cout << u8"E-posta (isteg bagli): ";
                std::getline(std::cin, email);
                
                // 🛡️ VERİ GÜVENLİĞİ: Email validation (data_security modülü)
                if (!email.empty() && !Kerem::DataSecurity::validateInput(email, Kerem::DataSecurity::InputType::EMAIL)) {
                    std::cout << u8"\n⚠ Gecersiz e-posta formati!\n";
                    std::cout << u8"Devam etmek icin Enter tusuna basin...";
                    std::cin.get();
                    continue;
                }

                // 🛡️ VERİ GÜVENLİĞİ: SecureString ile hassas veri yönetimi (data_security modülü)
                Kerem::DataSecurity::SecureString securePassword(password);
                
                if (auth.registerUser(db, username, securePassword.get(), email)) {
                    std::cout << u8"\n✓ Kayit basarili! Simdi giris yapabilirsiniz.\n";
                    std::cout << u8"Devam etmek icin Enter tusuna basin...";
                    std::cin.get();
                } else {
                    std::cout << u8"\n⚠ Kayit basarisiz! Kullanici adi zaten kullanimda veya gecersiz veri.\n";
                    std::cout << u8"Devam etmek icin Enter tusuna basin...";
                    std::cin.get();
                }
                
                // Hassas verileri temizle
                password.clear();
                password.shrink_to_fit();
            }
            else if (choice == 2) {
                // 🛡️ VERİ GÜVENLİĞİ: Güvenli giriş
                clearScreen();
                std::cout << u8"\n=== Giris Yap ===\n";
                std::string username;
                
                std::cout << u8"Kullanici adi: ";
                std::getline(std::cin, username);
                
                std::cout << u8"Sifre: ";
                std::string password = getPasswordMasked();

                // 🛡️ VERİ GÜVENLİĞİ: SecureString ile password yönetimi (data_security modülü)
                Kerem::DataSecurity::SecureString securePassword(password);
                
                int userId = auth.loginUser(db, username, securePassword.get());
                if (userId > 0) {
                    std::cout << u8"\n✓ Giris basarili! Hos geldiniz, " << username << "!\n";
                    std::cout << u8"Devam etmek icin Enter tusuna basin...";
                    std::cin.get();
                    
                    // Hassas verileri temizle
                    password.clear();
                    password.shrink_to_fit();
                    
                    return userId; // Basarili giris
                } else {
                    std::cout << u8"\n⚠ Giris basarisiz! Kullanici adi veya sifre hatali.\n";
                    std::cout << u8"Devam etmek icin Enter tusuna basin...";
                    std::cin.get();
                }
                
                // Hassas verileri temizle
                password.clear();
                password.shrink_to_fit();
            }
            else {
                std::cout << u8"Gecersiz secim!\n";
            }
        }
    }

} // namespace

void runApplication() {
#ifdef _WIN32
    // Konsolda Türkçe karakterlerin bozulmaması için UTF-8 kod sayfasına geç
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
#endif
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(nullptr);

    // Veritabanı yöneticisi
    DatabaseManager db;
    bool dbOpened = false;
    
    // 📂 Veritabanı dosyası - executable'ın bulunduğu dizinde oluştur
    std::string dbFilePath;
#ifdef _WIN32
    // Windows: Executable'ın bulunduğu dizini al
    char exePath[MAX_PATH];
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH)) {
        std::string exePathStr(exePath);
        size_t lastSlash = exePathStr.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            std::string exeDir = exePathStr.substr(0, lastSlash + 1);
            dbFilePath = exeDir + "personal_finance.db";
        } else {
            // Fallback: çalışma dizini
            dbFilePath = "personal_finance.db";
        }
    } else {
        // Fallback: çalışma dizini
        dbFilePath = "personal_finance.db";
    }
#else
    // Linux/Mac: Executable'ın bulunduğu dizini al
    char exePath[1024];
    ssize_t count = readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
    if (count != -1) {
        exePath[count] = '\0';
        std::string exePathStr(exePath);
        size_t lastSlash = exePathStr.find_last_of("/");
        if (lastSlash != std::string::npos) {
            std::string exeDir = exePathStr.substr(0, lastSlash + 1);
            dbFilePath = exeDir + "personal_finance.db";
        } else {
            dbFilePath = "personal_finance.db";
        }
    } else {
        dbFilePath = "personal_finance.db";
    }
#endif
    
    // Veritabanini ac ve tablolari olustur
    if (db.open(dbFilePath)) {
        if (db.createTables()) {
            dbOpened = true;
            std::cout << u8"✓ Veritabani basariyla acildi ve hazir.\n";
            std::cout << u8"📂 Veritabani dosyasi: " << dbFilePath << "\n";
        } else {
            std::cout << u8"⚠ Veritabani tablolari olusturulamadi: " << db.getLastError() << "\n";
        }
    } else {
        std::cout << u8"⚠ Veritabani acilamadi: " << db.getLastError() << "\n";
        std::cout << u8"Veriler yalnizca bu oturum icin gecerli olacak.\n";
    }

    // Kullanıcı kimlik doğrulama
    UserAuth auth;
    int currentUserId = -1;
    std::string currentUsername;

    if (dbOpened) {
        // Login/Register menüsünü göster
        currentUserId = showAuthMenu(db, auth);
        
        if (currentUserId <= 0) {
            // Kullanici cikis yapti
            std::cout << u8"\nGule gule!\n";
            return;
        }

        // Kullanici bilgilerini al
        User currentUser;
        if (auth.getUserById(db, currentUserId, currentUser)) {
            currentUsername = currentUser.username;
        }
    }

    BudgetManager        budget;
    InvestmentPortfolio  portfolio;
    GoalsManager         goals;
    DebtManager          debts;

    // Veritabanından kullanıcıya özel verileri yükle
    if (dbOpened) {
        budget.loadFromDatabase(db, currentUserId);
        portfolio.loadFromDatabase(db, currentUserId);
        goals.loadFromDatabase(db, currentUserId);
        debts.loadFromDatabase(db, currentUserId);
        std::cout << u8"\n✓ Verileriniz yuklendi.\n";
        std::cout << u8"Devam etmek icin Enter tusuna basin...";
        std::cin.get();
    }

    while (true) {
        clearScreen();
        // >>> RENKLİ/EMOJİLİ ANA MENÜ <<<
        mainMenuVisual(currentUsername);

        int sel;
        if (!(std::cin >> sel)) { clearCin(); continue; }
        clearCin();

        if (sel == 0) break;

        switch (sel) {
        case 1: { // ------- BUTCE -------
            clearScreen();
            std::cout << "-- Butce --\n";
            std::cout << "1) Gelir ekle\n"
                "2) Gider ekle\n"
                "3) Kategori limiti belirle\n"
                "4) Ozet/uyarilar\n";
            int s; if (!readIntSafe("Secim: ", s)) break;

            if (s == 1) {
                double a; std::cout << "Gelir tutari: ";
                if (!(std::cin >> a)) { clearCin(); break; } clearCin();
                budget.addIncome(a);
                std::cout << u8"✓ Gelir eklendi.\n";
                if (dbOpened) {
                    if (budget.saveToDatabase(db, currentUserId)) {
                        std::cout << u8"💾 Veritabanina kaydedildi.\n";
                    } else {
                        std::cout << u8"⚠ Veritabanina kaydedilemedi!\n";
                    }
                }
            }
            else if (s == 2) {
                std::string cat; double a;
                std::cout << "Kategori: "; std::getline(std::cin, cat);
                std::cout << "Tutar: ";
                if (!(std::cin >> a)) { clearCin(); break; } clearCin();
                budget.addExpense(cat, a);
                std::cout << u8"✓ Gider eklendi.\n";
                if (dbOpened) {
                    if (budget.saveToDatabase(db, currentUserId)) {
                        std::cout << u8"💾 Veritabanina kaydedildi.\n";
                    } else {
                        std::cout << u8"⚠ Veritabanina kaydedilemedi!\n";
                    }
                }
            }
            else if (s == 3) {
                std::string cat; double lim;
                std::cout << "Kategori: "; std::getline(std::cin, cat);
                std::cout << "Limit: ";
                if (!(std::cin >> lim)) { clearCin(); break; } clearCin();
                budget.setCategoryLimit(cat, lim);
                std::cout << u8"✓ Limit ayarlandi.\n";
                if (dbOpened) {
                    if (budget.saveToDatabase(db, currentUserId)) {
                        std::cout << u8"💾 Veritabanina kaydedildi.\n";
                    } else {
                        std::cout << u8"⚠ Veritabanina kaydedilemedi!\n";
                    }
                }
            }
            else if (s == 4) {
                std::cout << "Toplam gelir: " << budget.getTotalIncome() << "\n";
                std::cout << "Toplam gider: " << budget.getTotalExpenses() << "\n";
                std::cout << "Bakiye: " << budget.getBalance() << "\n";
                for (const auto& kv : budget.getCategories()) {
                    const auto& c = kv.second;
                    auto alert = budget.getCategoryAlert(c.name);
                    if (!alert.empty()) std::cout << alert << "\n";
                }
            }
            std::cout << "Devam etmek icin Enter...\n"; std::cin.get();
            break;
        }
        case 2: { // ------- PORTFOY -------
            clearScreen();
            std::cout << "-- Portfoy --\n";
            std::cout << "1) Yatirim ekle\n2) Ozet ve oneri\n";
            int s; if (!readIntSafe("Secim: ", s)) break;

            if (s == 1) {
                Investment inv{};
                std::cout << "Sembol: "; std::getline(std::cin, inv.symbol);
                std::cout << "Adet/lot: ";
                if (!(std::cin >> inv.units)) { clearCin(); break; } clearCin();
                std::cout << "Mevcut fiyat: ";
                if (!(std::cin >> inv.currentPrice)) { clearCin(); break; } clearCin();
                std::cout << "Maliyet (birim): ";
                if (!(std::cin >> inv.costBasisPerUnit)) { clearCin(); break; } clearCin();
                portfolio.addInvestment(inv);
                std::cout << u8"✓ Yatirim eklendi.\n";
                if (dbOpened) {
                    if (portfolio.saveToDatabase(db, currentUserId)) {
                        std::cout << u8"💾 Veritabanina kaydedildi.\n";
                    } else {
                        std::cout << u8"⚠ Veritabanina kaydedilemedi!\n";
                    }
                }
            }
            else if (s == 2) {
                std::cout << "Toplam deger: " << portfolio.getTotalMarketValue() << "\n";
                std::cout << "Toplam maliyet: " << portfolio.getTotalCost() << "\n";
                std::cout << "Gerceklesmemis PnL: " << portfolio.getTotalUnrealizedPnL() << "\n";
                std::cout << "Oneri: " << portfolio.getBasicSuggestion() << "\n";
            }
            std::cout << "Devam etmek icin Enter...\n"; std::cin.get();
            break;
        }
        case 3: { // ------- HEDEFLER -------
            clearScreen();
            std::cout << "-- Hedefler --\n";
            std::cout << "1) Hedef ekle\n2) Katki yap\n3) Ilerleme\n";
            int s; if (!readIntSafe("Secim: ", s)) break;

            if (s == 1) {
                std::string n; double t;
                std::cout << "Ad: "; std::getline(std::cin, n);
                std::cout << "Hedef tutar: ";
                if (!(std::cin >> t)) { clearCin(); break; } clearCin();
                goals.addGoal(n, t);
                std::cout << u8"✓ Hedef eklendi.\n";
                if (dbOpened) {
                    if (goals.saveToDatabase(db, currentUserId)) {
                        std::cout << u8"💾 Veritabanina kaydedildi.\n";
                    } else {
                        std::cout << u8"⚠ Veritabanina kaydedilemedi!\n";
                    }
                }
            }
            else if (s == 2) {
                std::string n; double a;
                std::cout << "Hedef adi: "; std::getline(std::cin, n);
                std::cout << "Katki tutari: ";
                if (!(std::cin >> a)) { clearCin(); break; } clearCin();
                goals.contribute(n, a);
                std::cout << u8"✓ Katki islendi.\n";
                if (dbOpened) {
                    if (goals.saveToDatabase(db, currentUserId)) {
                        std::cout << u8"💾 Veritabanina kaydedildi.\n";
                    } else {
                        std::cout << u8"⚠ Veritabanina kaydedilemedi!\n";
                    }
                }
            }
            else if (s == 3) {
                for (const auto& g : goals.getGoals()) {
                    std::cout << g.name << ": "
                        << goals.getProgressPercent(g.name)
                        << "% (" << g.savedAmount << "/" << g.targetAmount << ")\n";
                }
            }
            std::cout << "Devam etmek icin Enter...\n"; std::cin.get();
            break;
        }
        case 4: { // ------- BORCLAR -------
            clearScreen();
            std::cout << "-- Borclar --\n";
            std::cout << "1) Borc ekle\n2) Ozet ve strateji\n";
            int s; if (!readIntSafe("Secim: ", s)) break;

            if (s == 1) {
                Debt d{};
                std::cout << "Borc adi: "; std::getline(std::cin, d.name);
                std::cout << "Anapara: ";
                if (!(std::cin >> d.principal)) { clearCin(); break; } clearCin();
                std::cout << "Yillik faiz %: ";
                if (!(std::cin >> d.annualRatePercent)) { clearCin(); break; } clearCin();
                std::cout << "Asgari aylik odeme: ";
                if (!(std::cin >> d.minMonthlyPayment)) { clearCin(); break; } clearCin();
                d.paidSoFar = 0.0;
                debts.addDebt(d);
                std::cout << u8"✓ Borc eklendi.\n";
                if (dbOpened) {
                    if (debts.saveToDatabase(db, currentUserId)) {
                        std::cout << u8"💾 Veritabanina kaydedildi.\n";
                    } else {
                        std::cout << u8"⚠ Veritabanina kaydedilemedi!\n";
                    }
                }
            }
            else if (s == 2) {
                std::cout << "Toplam anapara: " << debts.getTotalPrincipal() << "\n";
                std::cout << "Tahmini aylik faiz: " << debts.getEstimatedMonthlyInterest() << "\n";
                std::cout << debts.getBasicPaydownSuggestion() << "\n";
            }
            std::cout << "Devam etmek icin Enter...\n"; std::cin.get();
            break;
        }
        case 5: { // ------- GÜVENLİ İLETİŞİM DEMO -------
            using namespace Kerem::personal::SecureCommunication;
            clearScreen();
            std::cout << u8"\n";
            drawLine();
            std::cout << u8"       🔐 Guvenli Iletisim Demo\n";
            drawLine();
            std::cout << u8" 1) Oturum Anahtari Olustur\n";
            std::cout << u8" 2) Mesaj Sifrele\n";
            std::cout << u8" 3) Mesaj Coz\n";
            std::cout << u8" 4) Anahtar Rotasyonu\n";
            std::cout << u8" 5) Paroladan Anahtar Turet (PBKDF2)\n";
            std::cout << u8" 6) Sertifika Pin Ekle\n";
            std::cout << u8" 7) TLS Context Bilgisi\n";
            std::cout << u8" 0) Ana Menuye Don\n";
            drawLine();
            
            int secureChoice;
            if (!readIntSafe("Seciminiz: ", secureChoice)) break;
            
            // Static session key manager (demo için)
            static SessionKeyManager demoKeyMgr;
            static CertificatePinning demoPinning;
            static std::string lastEncryptedHex;
            static EncryptedData lastEncrypted;
            
            switch (secureChoice) {
            case 1: { // Oturum anahtarı oluştur
                std::cout << u8"\n🔑 Yeni oturum anahtari olusturuluyor...\n";
                auto key = demoKeyMgr.generateSessionKey();
                std::cout << u8"✓ 256-bit AES anahtari olusturuldu!\n";
                std::cout << u8"Anahtar (hex): " << bytesToHex(key).substr(0, 32) << "...\n";
                std::cout << u8"Anahtar uzunlugu: " << key.size() << " byte\n";
                break;
            }
            case 2: { // Mesaj şifrele
                if (!demoKeyMgr.hasKey()) {
                    std::cout << u8"\n⚠ Once bir oturum anahtari olusturun (Secim 1)!\n";
                    break;
                }
                std::cout << u8"\nSifrelenecek mesaj: ";
                std::string message;
                std::getline(std::cin, message);
                if (message.empty()) {
                    std::cout << u8"⚠ Bos mesaj girildi!\n";
                    break;
                }
                try {
                    lastEncrypted = demoKeyMgr.encryptString(message);
                    lastEncryptedHex = bytesToHex(lastEncrypted.ciphertext);
                    std::cout << u8"\n✓ Mesaj AES-256-GCM ile sifrelendi!\n";
                    std::cout << u8"Sifreli veri (hex): " << lastEncryptedHex.substr(0, 40);
                    if (lastEncryptedHex.length() > 40) std::cout << "...";
                    std::cout << "\n";
                    std::cout << u8"IV (hex): " << bytesToHex(lastEncrypted.iv) << "\n";
                    std::cout << u8"Tag (hex): " << bytesToHex(lastEncrypted.tag).substr(0, 16) << "...\n";
                } catch (const std::exception& e) {
                    std::cout << u8"⚠ Sifreleme hatasi: " << e.what() << "\n";
                }
                break;
            }
            case 3: { // Mesaj çöz
                if (!demoKeyMgr.hasKey()) {
                    std::cout << u8"\n⚠ Once bir oturum anahtari olusturun (Secim 1)!\n";
                    break;
                }
                if (lastEncryptedHex.empty()) {
                    std::cout << u8"\n⚠ Once bir mesaj sifreleyin (Secim 2)!\n";
                    break;
                }
                try {
                    std::string decrypted = demoKeyMgr.decryptToString(lastEncrypted);
                    std::cout << u8"\n✓ Mesaj basariyla cozuldu!\n";
                    std::cout << u8"Cozulen mesaj: " << decrypted << "\n";
                } catch (const std::exception& e) {
                    std::cout << u8"⚠ Cozme hatasi: " << e.what() << "\n";
                }
                break;
            }
            case 4: { // Anahtar rotasyonu
                if (!demoKeyMgr.hasKey()) {
                    std::cout << u8"\n⚠ Once bir oturum anahtari olusturun (Secim 1)!\n";
                    break;
                }
                std::cout << u8"\n🔄 Anahtar rotasyonu yapiliyor...\n";
                std::cout << u8"Eski anahtar kullanim sayisi: " << demoKeyMgr.getKeyUsageCount() << "\n";
                auto newKey = demoKeyMgr.rotateSessionKey();
                std::cout << u8"✓ Yeni anahtar olusturuldu!\n";
                std::cout << u8"Yeni anahtar (hex): " << bytesToHex(newKey).substr(0, 32) << "...\n";
                std::cout << u8"⚠ Eski anahtarla sifrelenmis veriler artik cozulemez!\n";
                lastEncryptedHex.clear();
                break;
            }
            case 5: { // PBKDF2 anahtar türetme
                std::cout << u8"\n🔑 Paroladan Anahtar Turetme (PBKDF2-HMAC-SHA256)\n";
                std::cout << u8"Parola girin: ";
                std::string password;
                std::getline(std::cin, password);
                if (password.empty()) {
                    std::cout << u8"⚠ Bos parola girildi!\n";
                    break;
                }
                try {
                    auto salt = SessionKeyManager::generateSalt();
                    std::cout << u8"\nSalt (rastgele, hex): " << bytesToHex(salt) << "\n";
                    std::cout << u8"Iterasyon sayisi: 100,000\n";
                    auto derivedKey = SessionKeyManager::deriveKeyFromPassword(password, salt);
                    std::cout << u8"\n✓ Anahtar turetildi!\n";
                    std::cout << u8"Turetilen anahtar (hex): " << bytesToHex(derivedKey).substr(0, 32) << "...\n";
                    std::cout << u8"Anahtar uzunlugu: " << derivedKey.size() << " byte (256-bit)\n";
                } catch (const std::exception& e) {
                    std::cout << u8"⚠ Turetme hatasi: " << e.what() << "\n";
                }
                break;
            }
            case 6: { // Sertifika pin ekle
                std::cout << u8"\n📌 Sertifika Pin Ekleme\n";
                std::cout << u8"Hostname (ornek: api.example.com): ";
                std::string hostname;
                std::getline(std::cin, hostname);
                if (hostname.empty()) {
                    std::cout << u8"⚠ Bos hostname girildi!\n";
                    break;
                }
                // Demo için sahte bir hash oluştur
                auto demoHash = SessionKeyManager::generateSalt();
                auto demoHash2 = SessionKeyManager::generateSalt();
                std::vector<uint8_t> fullHash;
                fullHash.insert(fullHash.end(), demoHash.begin(), demoHash.end());
                fullHash.insert(fullHash.end(), demoHash2.begin(), demoHash2.end());
                std::string hashHex = bytesToHex(fullHash);
                
                if (demoPinning.addPinnedCertificate(hostname, hashHex)) {
                    std::cout << u8"\n✓ Sertifika pini eklendi!\n";
                    std::cout << u8"Hostname: " << hostname << "\n";
                    std::cout << u8"SHA-256 Hash: " << hashHex.substr(0, 32) << "...\n";
                    std::cout << u8"Toplam pin sayisi: " << demoPinning.getPinCount() << "\n";
                } else {
                    std::cout << u8"⚠ Pin eklenemedi!\n";
                }
                break;
            }
            case 7: { // TLS Context bilgisi
                std::cout << u8"\n🔒 TLS Context Bilgisi\n";
                TLSContext ctx;
                TLSConfig config;
                config.verifyPeer = false;
                if (ctx.initialize(config)) {
                    std::cout << u8"✓ TLS Context basariyla olusturuldu!\n";
                    std::cout << u8"TLS Versiyonu: " << ctx.getTLSVersion() << "\n";
                    auto ciphers = ctx.getSupportedCipherSuites();
                    std::cout << u8"Desteklenen Cipher Suite sayisi: " << ciphers.size() << "\n";
                    if (!ciphers.empty()) {
                        std::cout << u8"Ornek cipher'lar:\n";
                        for (size_t i = 0; i < std::min(size_t(3), ciphers.size()); ++i) {
                            std::cout << u8"  - " << ciphers[i] << "\n";
                        }
                    }
                } else {
                    std::cout << u8"⚠ TLS Context olusturulamadi!\n";
                }
                break;
            }
            case 0:
                break;
            default:
                std::cout << u8"Gecersiz secim!\n";
                break;
            }
            std::cout << u8"\nDevam etmek icin Enter...\n"; std::cin.get();
            break;
        }
        default:
            std::cout << "Gecersiz secim.\n";
            std::cout << "Devam etmek icin Enter...\n"; std::cin.get();
            break;
        }
    }

    // 💾 Cikis oncesi tum verileri kaydet
    if (dbOpened && currentUserId > 0) {
        std::cout << u8"\n💾 Verileriniz kaydediliyor...\n";
        bool saveSuccess = true;
        
        if (!budget.saveToDatabase(db, currentUserId)) {
            std::cout << u8"⚠ Butce verileri kaydedilemedi!\n";
            saveSuccess = false;
        }
        if (!portfolio.saveToDatabase(db, currentUserId)) {
            std::cout << u8"⚠ Portfoy verileri kaydedilemedi!\n";
            saveSuccess = false;
        }
        if (!goals.saveToDatabase(db, currentUserId)) {
            std::cout << u8"⚠ Hedef verileri kaydedilemedi!\n";
            saveSuccess = false;
        }
        if (!debts.saveToDatabase(db, currentUserId)) {
            std::cout << u8"⚠ Borc verileri kaydedilemedi!\n";
            saveSuccess = false;
        }
        
        if (saveSuccess) {
            std::cout << u8"✓ Tum verileriniz basariyla kaydedildi.\n";
        }
    }

    std::cout << u8"\nGule gule!\n";
}

int main() {
    // 🛡️ RASP: Runtime Application Self-Protection başlat
    // Bu çağrı, uygulama başlamadan önce güvenlik kontrollerini yapar:
    // - Anti-debug kontrolü (debugger tespiti)
    // - Checksum doğrulama (kod bütünlüğü kontrolü)
    // Eğer güvenlik ihlali tespit edilirse, uygulama terminate edilir.
    Kerem::personal::rasp::init();
    
    // Eğer init() başarılıysa, normal uygulama çalışır
    // Eğer güvenlik ihlali varsa, zaten terminate olmuştur (buraya gelmez)
    runApplication();
    return 0;
}