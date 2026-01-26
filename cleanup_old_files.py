import os, time

def cleanup_old_files():
    folder = "uploads"
    for f in os.listdir(folder):
        path = os.path.join(folder, f)
        if os.path.isfile(path) and f.endswith((".xlsx", ".xls")):
            if time.time() - os.path.getmtime(path) > 86400:  # 1 day
                os.remove(path)
