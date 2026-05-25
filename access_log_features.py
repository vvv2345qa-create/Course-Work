from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from collections import Counter
from typing import List, Dict
from urllib.parse import urlsplit, parse_qsl, unquote
import argparse
import csv
import pickle
import re
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from model_metrics import create_confusion_matrix_plot, print_classification_metrics

try:
    from sklearn.ensemble import IsolationForest
except ModuleNotFoundError:
    IsolationForest = None
TRAIN_PATH = Path("C:/Users/lenovo/Desktop/LL.txt")
TEST_PATH = Path("C:/Users/lenovo/Desktop/LLLL.txt")
OUTPUT_DIR = Path("C:/Users/lenovo/Desktop")
MODEL_PATH = OUTPUT_DIR / "isolation_forest_model.pkl"
GOOD_TRAIN_IP_PATH = OUTPUT_DIR / "good_test_ip.txt"
BAD_TRAIN_IP_PATH = OUTPUT_DIR / "bad_test_ip.txt"
GOOD_TEST_IP_PATH = OUTPUT_DIR / "good_train_ip.txt"
BAD_TEST_IP_PATH = OUTPUT_DIR / "bad_train_ip.txt"
names = ["method", "path", "protocol", "status", "size", "referrer", "user_agent"]
SUSPICIOUS_URL_WORDS = {
    "shell",
    "wget",
    "chmod",
    "wp-login",
    "wp-admin",
    "xmlrpc",
    "phpmyadmin",
    ".env",
    ".git",
    "backup",
    "config",
    "admin",
    "login",
    "select",
    "sleep",
    "union",
    "script",
    "etc",
    "passwd",
}
SUSPICIOUS_AGENT_WORDS = {
    "curl",
    "sqlmap",
    "nmap",
    "botnet",
    "nikto",
    "masscan",
    "python-requests",
    "ffuf",
    "gobuster",
    "hydra",
    "skipfish",
    "wpscan",
}
SCANNER_AGENT_WORDS = {
    "sqlmap",
    "nmap",
    "nikto",
    "masscan",
    "ffuf",
    "gobuster",
    "hydra",
    "skipfish",
    "wpscan",
}
BOTNET_AGENT_WORDS = {
    "botnet",
    "mirai",
    "mozi",
    "gafgyt",
    "bashlite",
}
SCANNER_URL_WORDS = {
    "wp-login",
    "wp-admin",
    "xmlrpc",
    "phpmyadmin",
    ".env",
    ".git",
    "admin",
    "login",
    "select",
    "sleep",
    "union",
    "script",
    "passwd",
}
BOTNET_URL_WORDS = {
    "shell",
    "wget",
    "chmod",
    "/tmp",
    "busybox",
    "bin",
    "cmd",
}


@dataclass
class Ip_Object:
    ip: str = ""
    timestamp: int = 0
    method: List[str] = field(default_factory=list)
    url_path: List[str] = field(default_factory=list)
    normalized_url_path: List[str] = field(default_factory=list)
    url_bigrams: Dict[str, int] = field(default_factory=dict)
    status: List[str] = field(default_factory=list)
    amount_of_status: Dict[str, int] = field(default_factory=dict)
    size: List[int] = field(default_factory=list)
    user_agent: List[str] = field(default_factory=list)
    amount_of_ip: int = 0

    def show_svoistva(self):
        print(
            f"ip is: {self.ip},method is:{self.method},url_path is: {self.url_path},"
            f"normalized_url_path is: {self.normalized_url_path},url_bigrams is: {self.url_bigrams},"
            f"status is: {self.status},amount_of_status is: {self.amount_of_status}, "
            f"the size is: {self.size},the user agent is: {self.user_agent}"
        )


def read_the_file(PATH):
    with open(PATH, "r", encoding="utf-8") as f:
        return f.read()


def parse_timestamp(timestamp):
    timestamp = timestamp.strip().split()[0]
    return datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S")


def parse_the_file(PATH):
    info = read_the_file(PATH)
    count_ip = {}
    sub_list_of_ip = {}
    ip_addr = []
    pattern = re.compile(
        r'(?P<ip>\S+) - - \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
        r'(?P<status>\d+) (?P<size>\d+|-) '
        r'"(?P<referrer>[^"]*)" '
        r'"(?P<user_agent>[^"]*)"'
    )

    for el in info.split("\n"):
        match = pattern.match(el)
        if match:
            data = match.groupdict()
            ip = data["ip"].strip()
            ip_addr.append(ip)
            datta = parse_timestamp(data["timestamp"])

            if ip not in count_ip:
                count_ip[ip] = 1
                sub_list_of_ip[ip] = [
                    [datta],
                    [data["method"]],
                    [data["path"]],
                    [data["protocol"]],
                    [data["status"]],
                    [data["size"]],
                    [data["referrer"]],
                    [data["user_agent"]],
                ]
            else:
                count_ip[ip] += 1
                j = 0
                for i in range(len(sub_list_of_ip[ip])):
                    if i == 0:
                        sub_list_of_ip[ip][i].append(datta)
                    else:
                        sub_list_of_ip[ip][i].append(data[names[j]])
                        j += 1

    return [count_ip, sub_list_of_ip, list(set(ip_addr))]


def count_average_time(time):
    i = 1
    prev = 0
    sum_in_seconds = 0
    while i < len(time):
        sum_in_seconds += abs(time[i] - time[prev]).total_seconds()
        prev = i
        i += 1
    return int(sum_in_seconds // (len(time) - 1)) if len(time) > 1 else sum_in_seconds


count_len_of_url = lambda url: [len(el) for el in url]


def count_status(status):
    return dict(Counter(status))


def normalize_value(value):
    value = unquote(value)
    if value == "":
        return "<EMPTY>"
    if re.fullmatch(r"\d+", value):
        return "<NUM>"
    if re.fullmatch(r"[0-9a-fA-F]{8,}", value):
        return "<HEX>"
    if re.fullmatch(r"[0-9a-fA-F-]{32,36}", value):
        return "<UUID>"
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
        return "<EMAIL>"
    return "<VALUE>"


def normalize_path_segment(segment):
    segment = unquote(segment).lower()
    if re.fullmatch(r"v\d+", segment):
        return segment
    if re.fullmatch(r"\d+", segment):
        return "<NUM>"
    if re.fullmatch(r"[0-9a-f]{8,}", segment):
        return "<HEX>"
    if re.fullmatch(r"[0-9a-f-]{32,36}", segment):
        return "<UUID>"
    return segment


def normalize_url(url):
    parts = urlsplit(url)
    path = unquote(parts.path or "/")
    path_segments = []

    for segment in path.split("/"):
        if not segment:
            continue
        path_segments.append(normalize_path_segment(segment))

    normalized_path = "/" + "/".join(path_segments)
    if not parts.query:
        return normalized_path

    query_parts = []
    parsed_query = parse_qsl(parts.query, keep_blank_values=True)

    if parsed_query:
        for key, value in parsed_query:
            query_parts.append(f"{key.lower()}={normalize_value(value)}")
    else:
        query_parts.append("<QUERY>")

    return normalized_path + "?" + "&".join(sorted(query_parts))


def tokenize_url(url):
    tokens = re.findall(r"[a-zA-Z_]+|<[^>]+>|\d+", url.lower())
    return tokens if tokens else ["<EMPTY_URL>"]


def make_n_grams(tokens, n=2):
    if len(tokens) < n:
        return [" ".join(tokens)]
    return [" ".join(tokens[i : i + n]) for i in range(len(tokens) - n + 1)]


def create_class(ip_list, data_list):
    classes = []
    for el in ip_list:
        obj = Ip_Object()
        for i in range(len(data_list[el])):
            if i == 0:
                obj.ip = el
                obj.timestamp = count_average_time(data_list[el][i])
            elif i == 1:
                obj.method = data_list[el][i]
            elif i == 2:
                obj.url_path = data_list[el][i]
                obj.size = count_len_of_url(data_list[el][i])
            elif i == 4:
                obj.status = data_list[el][i]
                obj.amount_of_status = count_status(data_list[el][i])
            elif i == 7:
                obj.user_agent = data_list[el][i]
        classes.append(obj)
    return classes


def add_class_to_list(lst_of_ob, count_i):
    for el in lst_of_ob:
        el.amount_of_ip = count_i[el.ip]


def normalize_urls(lst_of_ob):
    for el in lst_of_ob:
        el.normalized_url_path = [normalize_url(url) for url in el.url_path]


def tokenazi_the_url_params(lst_of_ob):
    for el in lst_of_ob:
        tokens = []
        for url in el.normalized_url_path:
            tokens.extend(tokenize_url(url))
        el.url_tokens = tokens


def count_n_gramms_for_url(lst_of_ob, n=2):
    for el in lst_of_ob:
        grams = []
        for url in el.normalized_url_path:
            grams.extend(make_n_grams(tokenize_url(url), n=n))
        el.url_bigrams = dict(Counter(grams))


def objects_to_feature_dicts(lst_of_ob):
    rows = []
    for el in lst_of_ob:
        method_counter = Counter(el.method)
        status_counter = Counter(el.status)
        suspicious_url_count = 0
        for url in el.normalized_url_path:
            lowered_url = url.lower()
            if any(word in lowered_url for word in SUSPICIOUS_URL_WORDS):
                suspicious_url_count += 1

        suspicious_user_agent_count = 0
        for user_agent in el.user_agent:
            lowered_agent = user_agent.lower()
            if any(word in lowered_agent for word in SUSPICIOUS_AGENT_WORDS):
                suspicious_user_agent_count += 1

        total_status = len(el.status) or 1
        row = {
            "amount_of_ip": el.amount_of_ip,
            "avg_seconds_between_requests": el.timestamp,
            "avg_url_len": sum(el.size) / len(el.size) if el.size else 0,
            "max_url_len": max(el.size) if el.size else 0,
            "unique_paths": len(set(el.normalized_url_path)),
            "unique_user_agents": len(set(el.user_agent)),
            "query_count": sum(1 for url in el.url_path if "?" in url),
            "suspicious_url_count": suspicious_url_count,
            "suspicious_user_agent_count": suspicious_user_agent_count,
            "error_4xx_count": sum(1 for status in el.status if status.startswith("4")),
            "error_5xx_count": sum(1 for status in el.status if status.startswith("5")),
        }

        row["error_ratio"] = (row["error_4xx_count"] + row["error_5xx_count"]) / total_status
        row["query_ratio"] = row["query_count"] / total_status
        row["status_200_ratio"] = status_counter.get("200", 0) / total_status
        row["status_302_ratio"] = status_counter.get("302", 0) / total_status
        row["status_403_ratio"] = status_counter.get("403", 0) / total_status
        row["status_404_ratio"] = status_counter.get("404", 0) / total_status
        row["status_5xx_ratio"] = row["error_5xx_count"] / total_status
        row["method_get_ratio"] = method_counter.get("GET", 0) / total_status
        row["method_post_ratio"] = method_counter.get("POST", 0) / total_status
        row["suspicious_url_ratio"] = suspicious_url_count / total_status
        row["suspicious_user_agent_ratio"] = suspicious_user_agent_count / total_status

        for method, count in method_counter.items():
            row[f"method_{method}"] = count

        for status, count in status_counter.items():
            row[f"status_{status}"] = count

        for bigram, count in el.url_bigrams.items():
            row[f"url_bigram_{bigram}"] = count

        rows.append(row)
    return rows


def feature_dicts_to_matrix(feature_dicts, feature_names=None):
    if feature_names is None:
        feature_names = sorted({key for row in feature_dicts for key in row})
    matrix = []
    for row in feature_dicts:
        matrix.append([row.get(name, 0) for name in feature_names])
    return matrix, feature_names


def prepare_data_for_model(PATH, feature_names=None):
    count_ip, sub_list_of_ip, ip_addr = parse_the_file(PATH)
    lst_of_obj = create_class(ip_addr, sub_list_of_ip)
    add_class_to_list(lst_of_obj, count_ip)
    normalize_urls(lst_of_obj)
    tokenazi_the_url_params(lst_of_obj)
    count_n_gramms_for_url(lst_of_obj, n=2)
    feature_dicts = objects_to_feature_dicts(lst_of_obj)
    matrix, feature_names = feature_dicts_to_matrix(feature_dicts, feature_names)
    ips = [obj.ip for obj in lst_of_obj]
    return lst_of_obj, matrix, feature_names, ips


def scale_matrix(matrix):
    X = np.array(matrix, dtype=float)
    mean = X.mean(axis=0)
    std = X.std(axis=0)
    std[std == 0] = 1
    return (X - mean) / std


def fit_scaler(matrix):
    X = np.array(matrix, dtype=float)
    mean = X.mean(axis=0)
    std = X.std(axis=0)
    std[std == 0] = 1
    return (X - mean) / std, {"mean": mean, "std": std}


def apply_scaler(matrix, scaler):
    X = np.array(matrix, dtype=float)
    return (X - scaler["mean"]) / scaler["std"]


def fit_isolation_forest(X, contamination=0.12, n_estimators=100, max_samples="auto", random_state=42):
    if IsolationForest is None:
        raise RuntimeError("Install scikit-learn: pip install scikit-learn")

    model = IsolationForest(
        n_estimators=n_estimators,
        max_samples=max_samples,
        contamination=contamination,
        random_state=random_state,
    )
    model.fit(X)
    return model


def score_isolation_forest(X, model):
    return -model.score_samples(X)


def predict_isolation_forest(X, model):
    return model.predict(X) == -1


def calibrate_anomaly_threshold(isolation_scores, true_labels):
    scores = np.array(isolation_scores, dtype=float)
    labels = np.array(true_labels, dtype=bool)
    best_threshold = float(scores.max()) if len(scores) else 0
    best_accuracy = -1

    for threshold in sorted(set(scores)):
        predictions = scores >= threshold
        accuracy = float(np.mean(predictions == labels))
        if accuracy > best_accuracy:
            best_accuracy = accuracy
            best_threshold = float(threshold)

    return best_threshold, best_accuracy


def predict_by_threshold(isolation_scores, threshold):
    return np.array(isolation_scores, dtype=float) >= threshold


def explain_ip(obj):
    reasons = []
    statuses = Counter(obj.status)
    agents = " ".join(obj.user_agent).lower()
    urls = " ".join(obj.normalized_url_path).lower()

    if sum(1 for status in obj.status if status.startswith("4")):
        reasons.append(f"4xx={sum(1 for status in obj.status if status.startswith('4'))}")
    if sum(1 for status in obj.status if status.startswith("5")):
        reasons.append(f"5xx={sum(1 for status in obj.status if status.startswith('5'))}")
    if any(word in agents for word in SUSPICIOUS_AGENT_WORDS):
        reasons.append("suspicious_user_agent")
    found_words = sorted(word for word in SUSPICIOUS_URL_WORDS if word in urls)
    if found_words:
        reasons.append("url:" + ",".join(found_words[:4]))
    if obj.amount_of_ip >= 30:
        reasons.append(f"many_requests={obj.amount_of_ip}")
    if statuses.get("403", 0) >= 3:
        reasons.append(f"many_403={statuses.get('403', 0)}")
    return "; ".join(reasons) if reasons else "model_anomaly"


def classify_malicious_type(obj):
    agents = " ".join(obj.user_agent).lower()
    urls = " ".join(obj.normalized_url_path).lower()

    botnet_score = 0
    scanner_score = 0

    if any(word in agents for word in BOTNET_AGENT_WORDS):
        botnet_score += 3
    if any(word in urls for word in BOTNET_URL_WORDS):
        botnet_score += 2
    if "wget" in urls and ("chmod" in urls or "shell" in urls):
        botnet_score += 3

    if any(word in agents for word in SCANNER_AGENT_WORDS):
        scanner_score += 3
    if any(word in urls for word in SCANNER_URL_WORDS):
        scanner_score += 2
    if "union" in urls or "select" in urls or "sleep" in urls:
        scanner_score += 2

    return "botnet" if botnet_score > scanner_score else "scanner"


def heuristic_true_label(obj):
    statuses = Counter(obj.status)
    agents = " ".join(obj.user_agent).lower()
    urls = " ".join(obj.normalized_url_path).lower()
    total_requests = len(obj.status) or 1
    error_count = sum(1 for status in obj.status if status.startswith("4") or status.startswith("5"))
    error_ratio = error_count / total_requests

    has_suspicious_agent = any(word in agents for word in SUSPICIOUS_AGENT_WORDS)
    has_suspicious_url = any(word in urls for word in SUSPICIOUS_URL_WORDS)
    has_many_forbidden = statuses.get("403", 0) >= 3
    has_high_error_ratio = error_ratio >= 0.7 and total_requests >= 3

    return bool(has_suspicious_agent or has_suspicious_url or has_many_forbidden or has_high_error_ratio)


def read_ip_file(path):
    path = Path(path)
    if not path.exists():
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


def load_ip_labels(good_ip_path=None, bad_ip_path=None):
    labels = {}

    if good_ip_path is not None:
        for ip in read_ip_file(good_ip_path):
            labels[ip] = False

    if bad_ip_path is not None:
        for ip in read_ip_file(bad_ip_path):
            labels[ip] = True

    return labels


def create_results_from_scores(lst_of_obj, isolation_scores, is_iforest_anomaly, ip_labels=None):
    ip_labels = ip_labels or {}
    results = []
    for i, obj in enumerate(lst_of_obj):
        model_score = float(isolation_scores[i])
        is_malicious = bool(is_iforest_anomaly[i])
        true_label = ip_labels.get(obj.ip, heuristic_true_label(obj))
        attack_type = classify_malicious_type(obj) if is_malicious else "normal"

        results.append(
            {
                "index": i,
                "ip": obj.ip,
                "requests": obj.amount_of_ip,
                "isolation_score": model_score,
                "final_score": model_score,
                "is_malicious": is_malicious,
                "attack_type": attack_type,
                "true_label": true_label,
                "is_correct": is_malicious == true_label,
                "reason": explain_ip(obj),
            }
        )

    results.sort(key=lambda row: (row["is_malicious"], row["final_score"]), reverse=True)
    return results


def train_isolation_model(
    PATH,
    model_path=MODEL_PATH,
    contamination=0.12,
    n_estimators=100,
    max_samples="auto",
    good_ip_path=None,
    bad_ip_path=None,
):
    lst_of_obj, matrix, feature_names, ips = prepare_data_for_model(PATH)
    ip_labels = load_ip_labels(good_ip_path, bad_ip_path)
    X_scaled, scaler = fit_scaler(matrix)
    forest_model = fit_isolation_forest(
        X_scaled,
        contamination=contamination,
        n_estimators=n_estimators,
        max_samples=max_samples,
    )
    isolation_scores = score_isolation_forest(X_scaled, forest_model)
    true_labels = [ip_labels.get(obj.ip, heuristic_true_label(obj)) for obj in lst_of_obj]
    anomaly_threshold, threshold_accuracy = calibrate_anomaly_threshold(isolation_scores, true_labels)
    is_iforest_anomaly = predict_by_threshold(isolation_scores, anomaly_threshold)

    model_state = {
        "feature_names": feature_names,
        "scaler": scaler,
        "forest_model": forest_model,
        "anomaly_threshold": anomaly_threshold,
        "threshold_accuracy": threshold_accuracy,
        "contamination": contamination,
        "trained_at": datetime.now().isoformat(timespec="seconds"),
        "train_path": str(PATH),
        "good_train_ip_path": str(good_ip_path) if good_ip_path else None,
        "bad_train_ip_path": str(bad_ip_path) if bad_ip_path else None,
    }

    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    with open(model_path, "wb") as f:
        pickle.dump(model_state, f)

    results = create_results_from_scores(lst_of_obj, isolation_scores, is_iforest_anomaly, ip_labels=ip_labels)
    return model_state, results, isolation_scores, model_path


def load_isolation_model(model_path=MODEL_PATH):
    with open(model_path, "rb") as f:
        return pickle.load(f)


def predict_with_saved_model(PATH, model_path=MODEL_PATH, good_ip_path=None, bad_ip_path=None):
    model_state = load_isolation_model(model_path)
    lst_of_obj, matrix, feature_names, ips = prepare_data_for_model(PATH, model_state["feature_names"])
    ip_labels = load_ip_labels(good_ip_path, bad_ip_path)
    X_scaled = apply_scaler(matrix, model_state["scaler"])
    isolation_scores = score_isolation_forest(X_scaled, model_state["forest_model"])
    if "anomaly_threshold" in model_state:
        is_iforest_anomaly = predict_by_threshold(isolation_scores, model_state["anomaly_threshold"])
    else:
        is_iforest_anomaly = predict_isolation_forest(X_scaled, model_state["forest_model"])
    results = create_results_from_scores(lst_of_obj, isolation_scores, is_iforest_anomaly, ip_labels=ip_labels)
    return model_state, results, isolation_scores


def create_visualizations(results, isolation_scores, output_dir=OUTPUT_DIR, prefix=""):
    output_dir.mkdir(parents=True, exist_ok=True)
    top_results = results[:15]
    plt.figure(figsize=(11, 6))
    plt.bar([row["ip"] for row in top_results], [row["final_score"] for row in top_results], color="#c73e3a")
    plt.title("Top suspicious IPs by Isolation Forest score")
    plt.xlabel("ip")
    plt.ylabel("score")
    plt.xticks(rotation=60, ha="right")
    plt.tight_layout()
    bar_path = output_dir / f"{prefix}top_suspicious_ips.png"
    plt.savefig(bar_path, dpi=160)
    plt.close()

    plt.figure(figsize=(10, 6))
    plt.hist(isolation_scores, bins=25, color="#2f6f9f", alpha=0.85)
    plt.title("Isolation Forest anomaly score distribution")
    plt.xlabel("anomaly score")
    plt.ylabel("ip count")
    plt.tight_layout()
    hist_path = output_dir / f"{prefix}isolation_score_distribution.png"
    plt.savefig(hist_path, dpi=160)
    plt.close()

    return [bar_path, hist_path]


def create_feature_correlation_plot(matrix, feature_names, output_dir=OUTPUT_DIR, filename="feature_correlation_matrix.png"):
    output_dir.mkdir(parents=True, exist_ok=True)
    X = np.array(matrix, dtype=float)

    if X.size == 0:
        return None

    std = X.std(axis=0)
    useful_indexes = np.where(std > 0)[0]
    if len(useful_indexes) == 0:
        return None

    X = X[:, useful_indexes]
    names = [feature_names[i] for i in useful_indexes]

    max_features = 35
    if len(names) > max_features:
        variances = X.var(axis=0)
        selected = np.argsort(variances)[-max_features:]
        X = X[:, selected]
        names = [names[i] for i in selected]

    corr = np.corrcoef(X, rowvar=False)
    corr = np.nan_to_num(corr)

    size = max(9, len(names) * 0.35)
    plt.figure(figsize=(size, size))
    plt.imshow(corr, cmap="coolwarm", vmin=-1, vmax=1)
    plt.colorbar(label="correlation")
    plt.xticks(range(len(names)), names, rotation=90, fontsize=7)
    plt.yticks(range(len(names)), names, fontsize=7)
    plt.title("Feature correlation matrix")
    plt.tight_layout()

    path = output_dir / filename
    plt.savefig(path, dpi=180)
    plt.close()
    return path


def create_attack_type_percentage_plot(results, output_dir=OUTPUT_DIR, filename="attack_type_percentage.png", title="Traffic classes"):
    output_dir.mkdir(parents=True, exist_ok=True)
    counts = Counter(row["attack_type"] for row in results)
    labels = ["normal", "scanner", "botnet"]
    values = [counts.get(label, 0) for label in labels]

    plt.figure(figsize=(7, 5))
    colors = ["#4c78a8", "#f58518", "#c73e3a"]

    if sum(values) == 0:
        values = [1, 0, 0]

    plt.pie(
        values,
        labels=labels,
        autopct="%1.1f%%",
        startangle=90,
        colors=colors,
    )
    plt.title(title)
    plt.tight_layout()

    path = output_dir / filename
    plt.savefig(path, dpi=160)
    plt.close()
    return path


def create_feature_radar_plot(matrix, feature_names, results, output_dir=OUTPUT_DIR, filename="feature_radar_profiles.png"):
    output_dir.mkdir(parents=True, exist_ok=True)
    X = np.array(matrix, dtype=float)

    if X.size == 0 or not results:
        return None

    radar_features = [
        "amount_of_ip",
        "avg_url_len",
        "max_url_len",
        "query_ratio",
        "error_ratio",
        "status_403_ratio",
        "status_404_ratio",
        "method_post_ratio",
        "suspicious_url_ratio",
        "suspicious_user_agent_ratio",
    ]
    label_map = {
        "amount_of_ip": "Requests",
        "avg_url_len": "Avg URL len",
        "max_url_len": "Max URL len",
        "query_ratio": "Query ratio",
        "error_ratio": "Error ratio",
        "status_403_ratio": "403 ratio",
        "status_404_ratio": "404 ratio",
        "method_post_ratio": "POST ratio",
        "suspicious_url_ratio": "Suspicious URL",
        "suspicious_user_agent_ratio": "Suspicious UA",
    }
    selected = [name for name in radar_features if name in feature_names]
    if not selected:
        return None

    indexes = [feature_names.index(name) for name in selected]
    values = X[:, indexes]
    min_values = values.min(axis=0)
    max_values = values.max(axis=0)
    denom = max_values - min_values
    denom[denom == 0] = 1
    normalized = (values - min_values) / denom

    groups = ["normal", "scanner", "botnet"]
    group_values = {}
    for group in groups:
        row_indexes = [row["index"] for row in results if row["attack_type"] == group and row["index"] < len(normalized)]
        if row_indexes:
            group_values[group] = normalized[row_indexes].mean(axis=0)
        else:
            group_values[group] = np.zeros(len(selected))

    labels = [label_map[name] for name in selected]

    angles = np.linspace(0, 2 * np.pi, len(selected), endpoint=False).tolist()
    angles += angles[:1]

    plt.figure(figsize=(10, 8))
    ax = plt.subplot(111, polar=True)

    colors = {
        "normal": "#4c78a8",
        "scanner": "#f58518",
        "botnet": "#c73e3a",
    }

    for group in groups:
        group_data = group_values[group].tolist()
        group_data += group_data[:1]
        ax.plot(angles, group_data, label=group, linewidth=2, color=colors[group])
        ax.fill(angles, group_data, alpha=0.12, color=colors[group])

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylim(0, 1)
    ax.set_title("Normalized feature profiles", pad=20)
    ax.legend(loc="upper right", bbox_to_anchor=(1.25, 1.1))
    plt.tight_layout()

    path = output_dir / filename
    plt.savefig(path, dpi=160)
    plt.close()
    return path


def calculate_accuracy(results):
    if not results:
        return 0
    correct = sum(1 for row in results if row["is_correct"])
    return correct / len(results)


def create_accuracy_plot(train_accuracy, test_accuracy, output_dir=OUTPUT_DIR):
    output_dir.mkdir(parents=True, exist_ok=True)
    labels = ["train", "test"]
    values = [train_accuracy, test_accuracy]

    plt.figure(figsize=(7, 5))
    bars = plt.bar(labels, values, color=["#4c78a8", "#f58518"])
    plt.ylim(0, 1)
    plt.ylabel("accuracy")
    plt.title("Isolation Forest accuracy")

    for bar, value in zip(bars, values):
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            min(value + 0.03, 0.98),
            f"{value:.2%}",
            ha="center",
        )

    plt.tight_layout()
    accuracy_path = output_dir / "train_test_accuracy.png"
    plt.savefig(accuracy_path, dpi=160)
    plt.close()
    return accuracy_path


def print_accuracy_report(train_results, test_results, accuracy_path):
    train_accuracy = calculate_accuracy(train_results)
    test_accuracy = calculate_accuracy(test_results)
    print("accuracy:")
    print(f"train_accuracy: {train_accuracy:.4f}")
    print(f"test_accuracy: {test_accuracy:.4f}")
    print("accuracy_plot:")
    print(accuracy_path)
    print()


def print_malicious_report(results, image_paths, top_n=20):
    malicious = [row for row in results if row["is_malicious"]]
    print("total_ips:", len(results))
    print("isolation_forest_suspicious_ips:", len(malicious))
    print()
    print("top_suspicious_ips:")
    for row in malicious[:top_n]:
        print(
            f"{row['ip']} | requests={row['requests']} | "
            f"type={row['attack_type']} | iforest={row['isolation_score']:.4f} | {row['reason']}"
        )
    print()
    print("plots:")
    for path in image_paths:
        print(path)


def save_results_to_csv(results, output_dir=OUTPUT_DIR, filename="malicious_ip_report.csv"):
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / filename
    fields = [
        "ip",
        "is_malicious",
        "attack_type",
        "true_label",
        "is_correct",
        "requests",
        "isolation_score",
        "final_score",
        "reason",
    ]
    try:
        f = open(csv_path, "w", encoding="utf-8", newline="")
    except PermissionError:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_path = output_dir / f"{Path(filename).stem}_{stamp}.csv"
        f = open(csv_path, "w", encoding="utf-8", newline="")

    with f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in results:
            writer.writerow({field: row[field] for field in fields})
    return csv_path


def train_access_log(PATH, model_path=MODEL_PATH, output_dir=OUTPUT_DIR, contamination=0.12):
    model_state, results, isolation_scores, saved_model_path = train_isolation_model(
        PATH,
        model_path=model_path,
        contamination=contamination,
        good_ip_path=GOOD_TRAIN_IP_PATH,
        bad_ip_path=BAD_TRAIN_IP_PATH,
    )
    image_paths = create_visualizations(results, isolation_scores, output_dir=output_dir)
    csv_path = save_results_to_csv(results, output_dir=output_dir)
    return results, image_paths, csv_path, saved_model_path


def predict_access_log(PATH, model_path=MODEL_PATH, output_dir=OUTPUT_DIR):
    model_state, results, isolation_scores = predict_with_saved_model(
        PATH,
        model_path=model_path,
        good_ip_path=GOOD_TEST_IP_PATH,
        bad_ip_path=BAD_TEST_IP_PATH,
    )
    image_paths = create_visualizations(results, isolation_scores, output_dir=output_dir)
    csv_path = save_results_to_csv(results, output_dir=output_dir)
    return results, image_paths, csv_path


def train_test_access_logs(
    train_path,
    test_path,
    model_path=MODEL_PATH,
    output_dir=OUTPUT_DIR,
    contamination=0.12,
    good_train_ip_path=GOOD_TRAIN_IP_PATH,
    bad_train_ip_path=BAD_TRAIN_IP_PATH,
    good_test_ip_path=GOOD_TEST_IP_PATH,
    bad_test_ip_path=BAD_TEST_IP_PATH,
):
    model_state, train_results, train_scores, saved_model_path = train_isolation_model(
        train_path,
        model_path=model_path,
        contamination=contamination,
        good_ip_path=good_train_ip_path,
        bad_ip_path=bad_train_ip_path,
    )
    model_state, test_results, test_scores = predict_with_saved_model(
        test_path,
        model_path=model_path,
        good_ip_path=good_test_ip_path,
        bad_ip_path=bad_test_ip_path,
    )

    train_image_paths = create_visualizations(train_results, train_scores, output_dir=output_dir, prefix="train_")
    test_image_paths = create_visualizations(test_results, test_scores, output_dir=output_dir, prefix="test_")
    train_objs, train_matrix, train_feature_names, train_ips = prepare_data_for_model(train_path)
    test_objs, test_matrix, test_feature_names, test_ips = prepare_data_for_model(test_path, train_feature_names)
    train_correlation_path = create_feature_correlation_plot(
        train_matrix,
        train_feature_names,
        output_dir=output_dir,
        filename="train_feature_correlation_matrix.png",
    )
    train_type_percentage_path = create_attack_type_percentage_plot(
        train_results,
        output_dir=output_dir,
        filename="train_attack_type_percentage.png",
        title="Train traffic classes",
    )
    test_type_percentage_path = create_attack_type_percentage_plot(
        test_results,
        output_dir=output_dir,
        filename="test_attack_type_percentage.png",
        title="Test traffic classes",
    )
    train_feature_radar_path = create_feature_radar_plot(
        train_matrix,
        train_feature_names,
        train_results,
        output_dir=output_dir,
        filename="train_feature_radar_profiles.png",
    )
    test_feature_radar_path = create_feature_radar_plot(
        test_matrix,
        train_feature_names,
        test_results,
        output_dir=output_dir,
        filename="test_feature_radar_profiles.png",
    )
    train_csv_path = save_results_to_csv(train_results, output_dir=output_dir, filename="train_malicious_ip_report.csv")
    test_csv_path = save_results_to_csv(test_results, output_dir=output_dir, filename="test_malicious_ip_report.csv")
    train_confusion_matrix_path = create_confusion_matrix_plot(
        train_results,
        output_dir=output_dir,
        filename="train_confusion_matrix.png",
        title="Isolation Forest train confusion matrix",
    )
    test_confusion_matrix_path = create_confusion_matrix_plot(
        test_results,
        output_dir=output_dir,
        filename="test_confusion_matrix.png",
        title="Isolation Forest test confusion matrix",
    )

    train_accuracy = calculate_accuracy(train_results)
    test_accuracy = calculate_accuracy(test_results)
    accuracy_path = create_accuracy_plot(train_accuracy, test_accuracy, output_dir=output_dir)

    return {
        "model_path": saved_model_path,
        "train_results": train_results,
        "test_results": test_results,
        "train_images": train_image_paths,
        "test_images": test_image_paths,
        "train_correlation_matrix": train_correlation_path,
        "train_type_percentage": train_type_percentage_path,
        "test_type_percentage": test_type_percentage_path,
        "train_feature_radar": train_feature_radar_path,
        "test_feature_radar": test_feature_radar_path,
        "train_csv": train_csv_path,
        "test_csv": test_csv_path,
        "train_confusion_matrix": train_confusion_matrix_path,
        "test_confusion_matrix": test_confusion_matrix_path,
        "accuracy_path": accuracy_path,
        "train_accuracy": train_accuracy,
        "test_accuracy": test_accuracy,
    }


def analyze_access_log(PATH, output_dir=OUTPUT_DIR):
    return predict_access_log(PATH, model_path=MODEL_PATH, output_dir=output_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("train_path", nargs="?", default=str(TRAIN_PATH))
    parser.add_argument("test_path", nargs="?", default=str(TEST_PATH))
    parser.add_argument("--model", default=str(MODEL_PATH))
    parser.add_argument("--contamination", type=float, default=0.12)
    parser.add_argument("--good-train-ip", default=str(GOOD_TRAIN_IP_PATH))
    parser.add_argument("--bad-train-ip", default=str(BAD_TRAIN_IP_PATH))
    parser.add_argument("--good-test-ip", default=str(GOOD_TEST_IP_PATH))
    parser.add_argument("--bad-test-ip", default=str(BAD_TEST_IP_PATH))
    args = parser.parse_args()

    report = train_test_access_logs(
        Path(args.train_path),
        Path(args.test_path),
        model_path=Path(args.model),
        contamination=args.contamination,
        good_train_ip_path=Path(args.good_train_ip),
        bad_train_ip_path=Path(args.bad_train_ip),
        good_test_ip_path=Path(args.good_test_ip),
        bad_test_ip_path=Path(args.bad_test_ip),
    )

    print("model:")
    print(report["model_path"])
    print_accuracy_report(report["train_results"], report["test_results"], report["accuracy_path"])
    print_classification_metrics(report["train_results"], title="train_metrics")
    print_classification_metrics(report["test_results"], title="test_metrics")

    print("train_csv:")
    print(report["train_csv"])
    print("test_csv:")
    print(report["test_csv"])
    print("train_confusion_matrix:")
    print(report["train_confusion_matrix"])
    print("test_confusion_matrix:")
    print(report["test_confusion_matrix"])
    print("train_feature_correlation_matrix:")
    print(report["train_correlation_matrix"])
    print("train_attack_type_percentage:")
    print(report["train_type_percentage"])
    print("test_attack_type_percentage:")
    print(report["test_type_percentage"])
    print("train_feature_radar:")
    print(report["train_feature_radar"])
    print("test_feature_radar:")
    print(report["test_feature_radar"])
    print()

    print("train_result:")
    print_malicious_report(report["train_results"], report["train_images"])
    print()

    print("test_result:")
    print_malicious_report(report["test_results"], report["test_images"])
