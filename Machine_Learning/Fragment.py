import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.utils import resample
# 如果想用 SMOTE，取消下一行註解 (pip install imblearn)
# from imblearn.over_sampling import SMOTE

# === 參數自行調整 ==================================
INPUT_CSV   = r"converted.csv"
TEST_RATIO  = 0.2      # 20% 當測試集
RANDOM_SEED = 42       # 可重現結果
# ====================================================

# --- 1. 讀取資料 -------------------------------------------------
df = pd.read_csv(INPUT_CSV, low_memory=False)
df['Label'] = df['Label'].str.strip()        # 防止空白差異
print(">>> 全資料筆數：")
print(df['Label'].value_counts(), '\n')

# --- 2. 切測試集（保持原始比例） -------------------------------
train_df, test_df = train_test_split(
    df,
    test_size=TEST_RATIO,
    random_state=RANDOM_SEED,
    shuffle=True      # 打散但不平衡化
)

print(">>> 測試集筆數（保持失衡）：")
print(test_df['Label'].value_counts(), '\n')

# --- 3. 在訓練集內做平衡 ---------------------------------------
#   (1) 取 BENIGN 與 非 BENIGN 兩群
benign_mask  = train_df['Label'] == 'BENIGN'
attack_mask  = ~benign_mask      # 其他都視為攻擊

benign_df  = train_df[benign_mask]
attack_df  = train_df[attack_mask]

#   (2) 選擇「少數類」的數量作為基準
minority_size = min(len(benign_df), len(attack_df))

#   (3-1) 下採樣多數類  ➜ 兩類一樣大
benign_down  = resample(benign_df,
                        replace=False,
                        n_samples=minority_size,
                        random_state=RANDOM_SEED)

attack_down  = resample(attack_df,
                        replace=False,
                        n_samples=minority_size,
                        random_state=RANDOM_SEED)

train_balanced = pd.concat([benign_down, attack_down], ignore_index=True)

#   (3-2) 你若想上採樣攻擊類，可改用 SMOTE (這段取代 3‑1)
"""
sm = SMOTE(random_state=RANDOM_SEED)
X = train_df.drop(columns=['Label'])
y = train_df['Label']
X_res, y_res = sm.fit_resample(X, y)
train_balanced = pd.concat([X_res, y_res], axis=1)
"""

print(">>> 平衡後的訓練集筆數：")
print(train_balanced['Label'].value_counts(), '\n')

# --- 4. 輸出結果 ----------------------------------------------
train_balanced.to_csv("2017_Train.csv", index=False)
test_df.to_csv("2017_Test.csv", index=False)

# 也把統計結果另存文字檔方便查
with open("train_balanced_stats.txt", "w", encoding="utf-8") as f:
    f.write("Training set after balancing:\n")
    f.write(str(train_balanced['Label'].value_counts()))

print("✅  已輸出：train_balanced.csv / test_raw.csv")
