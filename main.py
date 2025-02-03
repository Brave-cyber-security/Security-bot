import os
from typing import Dict, Union
import requests
import hashlib
import time
import telegram
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from urllib.parse import urlparse
import socket

class SecurityChecker:
    def __init__(self, vt_api_key: str):
        self.api_key = vt_api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.headers = {"apikey": vt_api_key}
    
    def check_url_exists(self, url: str) -> bool:
        """
        URL mavjudligini tekshirish
        """
        try:
            # URL ni parse qilish
            parsed = urlparse(url)
            if not parsed.netloc:
                return False
            
            # Domain ni olish
            domain = parsed.netloc
            if ":" in domain:
                domain = domain.split(":")[0]
            
            # DNS lookup orqali domain mavjudligini tekshirish
            socket.gethostbyname(domain)
            
            # URL ga so'rov yuborish
            response = requests.head(url, timeout=10, allow_redirects=True)
            return response.status_code < 400
            
        except (socket.gaierror, requests.RequestException):
            return False
        
    def _evaluate_risk(self, positives: int, total_scanners: int) -> Dict:
        """
        Evaluate risk based on detection ratio and provide detailed risk assessment
        """
        if total_scanners == 0:
            return {
                "safe_percentage": 0,
                "unsafe_percentage": 100,
                "risk_level": "critical"
            }
            
        unsafe_percentage = (positives / total_scanners * 100)
        safe_percentage = 100 - unsafe_percentage
        
        if positives > 0:
            if unsafe_percentage >= 15:
                risk_level = "critical"
            elif unsafe_percentage >= 5:
                risk_level = "high"
            elif unsafe_percentage >= 1:
                risk_level = "medium"
            else:
                risk_level = "low"
        else:
            risk_level = "low"
            
        return {
            "safe_percentage": round(safe_percentage, 2),
            "unsafe_percentage": round(unsafe_percentage, 2),
            "risk_level": risk_level
        }

    async def check_url(self, url: str) -> Dict:
        try:
            # URL mavjudligini tekshirish
            if not self.check_url_exists(url):
                raise Exception("URL mavjud emas yoki ochilmadi")
            
            # URL skanerlash
            scan_params = {"apikey": self.api_key, "url": url}
            scan_response = requests.post(f"{self.base_url}/url/scan", params=scan_params)
            
            if scan_response.status_code != 200:
                raise Exception("URL ni skanerlashda xatolik")
            
            # Natijani olish uchun kutish
            time.sleep(15)
            
            # Natijani olish
            report_params = {"apikey": self.api_key, "resource": url}
            response = requests.get(f"{self.base_url}/url/report", params=report_params)
            
            if response.status_code != 200:
                raise Exception("URL tekshirishda xatolik")

            results = response.json()
            if results.get("response_code") != 1:
                raise Exception("URL hali tekshirilmagan")

            scans = results.get("scans", {})
            total_scanners = len(scans)
            positives = results.get("positives", 0)
            
            detections = [
                f"{name}: {res.get('result', 'Xavf topildi')} ({res.get('detail', 'No details')})"
                for name, res in scans.items()
                if res.get("detected")
            ]

            risk_evaluation = self._evaluate_risk(positives, total_scanners)

            return {
                "url": url,
                "safe_percentage": risk_evaluation["safe_percentage"],
                "unsafe_percentage": risk_evaluation["unsafe_percentage"],
                "risk_level": risk_evaluation["risk_level"],
                "total_scanners": total_scanners,
                "detection_count": positives,
                "scan_date": results.get("scan_date"),
                "detections": detections,
                "permalink": results.get("permalink", "")
            }
        except Exception as e:
            raise Exception(f"URL tekshirishda xatolik: {str(e)}")

    async def check_file(self, file_path: str) -> Dict:
        try:
            if not os.path.exists(file_path):
                raise Exception("Fayl topilmadi")

            if os.path.getsize(file_path) > 32 * 1024 * 1024:
                raise Exception("Fayl hajmi juda katta (maksimum 32MB)")

            # Calculate file hash
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()

            # Get file report
            check_url = f"{self.base_url}/file/report"
            params = {"apikey": self.api_key, "resource": file_hash}
            response = requests.get(check_url, params=params)

            # If file hasn't been scanned before
            if response.status_code == 404 or response.json().get("response_code") == 0:
                scan_url = f"{self.base_url}/file/scan"
                with open(file_path, "rb") as f:
                    files = {"file": f}
                    response = requests.post(scan_url, files=files, headers=self.headers)

                if response.status_code != 200:
                    raise Exception("Faylni yuborishda xatolik")

                timeout = 90
                start_time = time.time()
                while True:
                    response = requests.get(check_url, params=params)
                    if response.json().get("response_code") == 1:
                        break
                    if time.time() - start_time > timeout:
                        raise TimeoutError("Tekshirish vaqti tugadi")
                    time.sleep(10)

            results = response.json()
            scans = results.get("scans", {})
            total_scanners = len(scans)
            positives = results.get("positives", 0)
            
            detections = [
                f"{name}: {res.get('result', 'Xavf topildi')} "
                f"(Version: {res.get('version', 'N/A')}, "
                f"Update: {res.get('update', 'N/A')})"
                for name, res in scans.items()
                if res.get("detected")
            ]

            risk_evaluation = self._evaluate_risk(positives, total_scanners)

            return {
                "filename": os.path.basename(file_path),
                "safe_percentage": risk_evaluation["safe_percentage"],
                "unsafe_percentage": risk_evaluation["unsafe_percentage"],
                "risk_level": risk_evaluation["risk_level"],
                "total_scanners": total_scanners,
                "detection_count": positives,
                "scan_date": results.get("scan_date"),
                "file_hash": file_hash,
                "detections": detections,
                "permalink": results.get("permalink", "")
            }
        except Exception as e:
            raise Exception(f"Fayl tekshirishda xatolik: {str(e)}")

class SecurityBot:
    def __init__(self, telegram_token: str, vt_api_key: str):
        self.checker = SecurityChecker(vt_api_key)
        self.application = Application.builder().token(telegram_token).build()
        
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("help", self.help_command))
        self.application.add_handler(MessageHandler(filters.Document.ALL, self.handle_file))
        self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_url))

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(
            "🔒 Xush kelibsiz! Men URL va fayllarni xavfsizlik uchun tekshiraman.\n\n"
            "📝 Foydalanish:\n"
            "- URL tekshirish: URL ni yuboring\n"
            "- Fayl tekshirish: Faylni yuboring\n\n"
            "ℹ️ /help - Qo'shimcha ma'lumot olish"
        )

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(
            "🔍 Bot qo'llanmasi:\n\n"
            "1️⃣ URL tekshirish:\n"
            "- URL ni http:// yoki https:// bilan yuboring\n"
            "- Bot URL ni viruslar va zararli kodlar uchun tekshiradi\n\n"
            "2️⃣ Fayl tekshirish:\n"
            "- Istalgan faylni botga yuboring (max 32MB)\n"
            "- Bot faylni xavfli elementlar uchun tekshiradi\n\n"
            "⚠️ Xavf darajalari:\n"
            "🟢 Past (0-1%)\n"
            "🟡 O'rta (1-5%)\n"
            "🔴 Yuqori (5-15%)\n"
            "⛔️ Kritik (15%+)"
        )

    def get_risk_emoji(self, risk_level: str) -> str:
        return {
            "low": "🟢",
            "medium": "🟡",
            "high": "🔴",
            "critical": "⛔️"
        }.get(risk_level, "⚠️")

    async def handle_url(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        url = update.message.text
        if not (url.startswith('http://') or url.startswith('https://')):
            await update.message.reply_text("❌ Noto'g'ri URL format. URL http:// yoki https:// bilan boshlanishi kerak")
            return

        status_message = await update.message.reply_text("🔄 URL tekshirilmoqda...")
        try:
            # URL mavjudligini tekshirish
            if not self.checker.check_url_exists(url):
                await status_message.edit_text("❌ URL mavjud emas yoki ochilmadi")
                return

            results = await self.checker.check_url(url)
            risk_emoji = self.get_risk_emoji(results['risk_level'])

            response_text = (
                f"🔍 URL tekshiruvi natijalari:\n\n"
                f"🔗 URL: {results['url']}\n"
                f"✅ Xavfsiz: {results['safe_percentage']}%\n"
                f"⚠️ Xavfli: {results['unsafe_percentage']}%\n"
                f"⭐️ Xavf darajasi: {risk_emoji} {results['risk_level'].upper()}\n"
                f"📊 Tekshiruv soni: {results['total_scanners']}\n"
                f"🕒 Sana: {results['scan_date']}\n"
                f"🔍 Batafsil: {results['permalink']}\n"
            )

            if results['detections']:
                response_text += "\n⚠️ Topilgan tahdidlar:\n"
                for detection in results['detections'][:5]:
                    response_text += f"❗️ {detection}\n"

            await status_message.edit_text(response_text)
        except Exception as e:
            await status_message.edit_text(f"❌ Xatolik yuz berdi: {str(e)}")

    async def handle_file(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        file_path = None
        status_message = None
        
        try:
            status_message = await update.message.reply_text("⬇️ Fayl yuklab olinmoqda...")
            
            safe_filename = ''.join(c for c in update.message.document.file_name if c.isalnum() or c in ('-', '_', '.'))
            file_path = f"temp_{int(time.time())}_{safe_filename}"
            
            try:
                file = await context.bot.get_file(update.message.document.file_id)
                await file.download_to_drive(file_path)
            except telegram.error.TimedOut:
                await status_message.edit_text("⚠️ Fayl yuklab olishda timeout xatosi yuz berdi. Iltimos, qayta urinib ko'ring.")
                return
            except Exception as e:
                await status_message.edit_text(f"⚠️ Faylni yuklab olishda xatolik: {str(e)}")
                return

            await status_message.edit_text("🔄 Fayl tekshirilmoqda...")
            
            results = await self.checker.check_file(file_path)
            risk_emoji = self.get_risk_emoji(results['risk_level'])
            
            response_text = (
                f"🔍 Fayl tekshiruvi natijalari:\n\n"
                f"📁 Fayl: {results['filename']}\n"
                f"✅ Xavfsiz: {results['safe_percentage']}%\n"
                f"⚠️ Xavfli: {results['unsafe_percentage']}%\n"
                f"⭐️ Xavf darajasi: {risk_emoji} {results['risk_level'].upper()}\n"
                f"📊 Tekshiruv soni: {results['total_scanners']}\n"
                f"🔒 Xesh: {results['file_hash']}\n"
                f"🕒 Sana: {results['scan_date']}\n"
                f"🔍 Batafsil: {results['permalink']}\n"
            )

            if results['detections']:
                response_text += "\n⚠️ Topilgan tahdidlar:\n"
                for detection in results['detections'][:5]:
                    response_text += f"❗️ {detection}\n"
            
            await status_message.edit_text(response_text)

        except Exception as e:
            error_message = f"❌ Xatolik yuz berdi: {str(e)}"
            if status_message:
                await status_message.edit_text(error_message)
            else:
                await update.message.reply_text(error_message)
        
        finally:
            if file_path and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception:
                    pass
    def run(self):
        """Botni ishga tushirish"""
        print("Bot ishga tushdi...")
        self.application.run_polling(allowed_updates=Update.ALL_TYPES)
def main():
    # Telegram bot tokeni va VirusTotal API kaliti
    TELEGRAM_TOKEN = "7157510574:AAHSBTwlOlc9v7T5Tgrcy4uEfz7aFJHPAgY"
    VIRUSTOTAL_API_KEY = "88c203c78362ea3c5c45cb8cb3f72c7c981a63d17134b8a027e8438c272cc099"
    
    try:
        # Botni yaratish va ishga tushirish
        print("Bot ishga tushirilmoqda...")
        bot = SecurityBot(TELEGRAM_TOKEN, VIRUSTOTAL_API_KEY)
        bot.run()
    except Exception as e:
        print(f"Botni ishga tushirishda xatolik: {str(e)}")

if __name__ == "__main__":
    main()
