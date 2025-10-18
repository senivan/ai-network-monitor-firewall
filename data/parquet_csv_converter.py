import pandas as pd
import os
import sys

if len(sys.argv) != 3:
    print("❌ python3 parquet_to_csv.py <вхідний.parquet> <вихідний.csv>")
    sys.exit(1)

input_file = sys.argv[1]
output_file = sys.argv[2]

try:
    print(f"🔄 Конвертація: {input_file} → {output_file}")
    df = pd.read_parquet(input_file)
    df.to_csv(output_file, index=False)
    print(f"✅ Успішно конвертовано: {output_file}")
except Exception as e:
    print(f"❌ Помилка під час конвертації: {e}")
    sys.exit(1)

if os.path.exists(output_file):
    print("📂 Перевіряємо перші 10 рядків CSV:")
    df_check = pd.read_csv(output_file)
    print(df_check.head(10))
else:
    print("😢 CSV файл не знайдено")
