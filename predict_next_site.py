import argparse
import glob
from collections import Counter
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split

class SeqDataset(Dataset):
    def __init__(self, X, y):
        self.X = torch.tensor(X, dtype=torch.long)
        self.y = torch.tensor(y, dtype=torch.long)

    def __len__(self):
        return len(self.X)

    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]

class NextSiteLSTM(nn.Module):
    def __init__(self, vocab_size, embed_dim=32, hidden=64):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim)
        self.lstm = nn.LSTM(embed_dim, hidden, batch_first=True)
        self.fc = nn.Linear(hidden, vocab_size)

    def forward(self, x):
        x = self.embedding(x)
        h, _ = self.lstm(x)
        return self.fc(h[:, -1])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", required=True, help="Path to directory with CSV logs")
    parser.add_argument("--user", required=True, help="src_ip of user to predict")
    parser.add_argument("--window", type=int, default=8)
    parser.add_argument("--epochs", type=int, default=15)
    args = parser.parse_args()

    files = sorted(glob.glob(f"{args.path}/*.csv"))
    if not files:
        raise RuntimeError("No CSV files found")

    df = pd.concat((pd.read_csv(f) for f in files), ignore_index=True)
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="mixed")
    df = df.sort_values("timestamp")
    df = df[df["direction"] == "outbound"]
    df["tls_sni"] = df["tls_sni"].fillna("NO_SNI")
    df = df[df["tls_sni"] != "NO_SNI"]

    print(f"[+] Events after filter: {len(df)}")
    print(f"[+] Users: {df['src_ip'].nunique()}")

    le = LabelEncoder()
    df["sni_id"] = le.fit_transform(df["tls_sni"])

    print(f"[+] Unique sites: {len(le.classes_)}")

    X, Y = [], []

    for ip, g in df.groupby("src_ip"):
        seq = g.sort_values("timestamp")["sni_id"].to_numpy()
        if len(seq) <= args.window:
            continue
        for i in range(len(seq) - args.window):
            X.append(seq[i:i + args.window])
            Y.append(seq[i + args.window])

    X = np.array(X)
    Y = np.array(Y)

    counter = Counter(Y)
    mask = np.array([counter[y] >= 2 for y in Y])
    X, Y = X[mask], Y[mask]

    print(f"[+] Sequences: {X.shape[0]}")

    X_train, _, y_train, _ = train_test_split(
        X, Y, test_size=0.2, random_state=42, stratify=Y
    )

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = NextSiteLSTM(len(le.classes_)).to(device)

    loader = DataLoader(
        SeqDataset(X_train, y_train),
        batch_size=64,
        shuffle=True
    )

    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.CrossEntropyLoss()

    print("[+] Training model...")
    for ep in range(args.epochs):
        losses = []
        for xb, yb in loader:
            xb, yb = xb.to(device), yb.to(device)
            opt.zero_grad()
            loss = loss_fn(model(xb), yb)
            loss.backward()
            opt.step()
            losses.append(loss.item())
        print(f"Epoch {ep+1}/{args.epochs} | loss={np.mean(losses):.4f}")

    user_df = df[df["src_ip"] == args.user]
    if len(user_df) < args.window:
        raise RuntimeError("Not enough history for this user")

    seq = user_df.sort_values("timestamp")["sni_id"].to_numpy()[-args.window:]
    x = torch.tensor(seq, dtype=torch.long).unsqueeze(0).to(device)

    model.eval()
    with torch.no_grad():
        logits = model(x)
        probs = torch.softmax(logits, dim=1)[0]
        top10 = torch.topk(probs, k=10).indices.cpu().numpy()

    sites = le.inverse_transform(top10)

    print("\n=== PREDICTED NEXT 10 SITES ===")
    for i, s in enumerate(sites, 1):
        print(f"{i:2d}. {s}")

if __name__ == "__main__":
    main()
