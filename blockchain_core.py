from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from collections import Counter
from typing import List, Dict
from urllib.parse import urlsplit, parse_qsl, unquote
import argparse
import csv
import math
import re
import matplotlib
from sklearn.ensemble import IsolationForest
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
PATH = Path("C:/Users/lenovo/Downloads/c.txt")
OUTPUT_DIR = Path("C:/Users/lenovo/Desktop")
GOOD_IPS=Path("C:/Users/lenovo/Desktop/good.txt")
BAD_IPS=Path("C:/Users/lenovo/Desktop/bad.txt")
names = ["method", "path", "protocol", "status", "size", "referrer", "user_agent"]
SUSPICIOUS_URL_WORDS = {
    "shell", "wget", "chmod", "wp-login", "admin", "login",
    "select", "sleep", "union", "script", "etc", "passwd",
}
SUSPICIOUS_AGENT_WORDS = {
    "curl", "sqlmap", "nmap", "botnet", "nikto", "masscan", "python-requests",
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
                    [datta], [data["method"]], [data["path"]], [data["protocol"]],
                    [data["status"]], [data["size"]], [data["referrer"]], [data["user_agent"]],
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
        if segment:
            path_segments.append(normalize_path_segment(segment))

    normalized_path = "/" + "/".join(path_segments)
    if not parts.query:
        return normalized_path

    parsed_query = parse_qsl(parts.query, keep_blank_values=True)
    query_parts = []

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
    return [" ".join(tokens[i:i + n]) for i in range(len(tokens) - n + 1)]


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

        suspicious_url_count = sum(
            1 for url in el.normalized_url_path
            if any(word in url.lower() for word in SUSPICIOUS_URL_WORDS)
        )

        suspicious_user_agent_count = sum(
            1 for user_agent in el.user_agent
            if any(word in user_agent.lower() for word in SUSPICIOUS_AGENT_WORDS)
        )

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


def feature_dicts_to_matrix(feature_dicts):
    feature_names = sorted({key for row in feature_dicts for key in row})
    matrix = []
    for row in feature_dicts:
        matrix.append([row.get(name, 0) for name in feature_names])
    return matrix, feature_names


def prepare_data_for_model(PATH):
    count_ip, sub_list_of_ip, ip_addr = parse_the_file(PATH)
    lst_of_obj = create_class(ip_addr, sub_list_of_ip)
    add_class_to_list(lst_of_obj, count_ip)
    normalize_urls(lst_of_obj)
    tokenazi_the_url_params(lst_of_obj)
    count_n_gramms_for_url(lst_of_obj, n=2)
    feature_dicts = objects_to_feature_dicts(lst_of_obj)
    matrix, feature_names = feature_dicts_to_matrix(feature_dicts)
    ips = [obj.ip for obj in lst_of_obj]
    return lst_of_obj, matrix, feature_names, ips


def scale_matrix(matrix):
    X = np.array(matrix, dtype=float)
    mean = X.mean(axis=0)
    std = X.std(axis=0)
    std[std == 0] = 1
    return (X - mean) / std


def c_factor(n):
    if n <= 1:
        return 0
    if n == 2:
        return 1
    return 2 * (math.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n)


def build_isolation_tree(X, depth, max_depth, rng):
    if depth >= max_depth or len(X) <= 1 or np.all(X == X[0]):
        return {"size": len(X)}

    possible_features = np.where(np.ptp(X, axis=0) > 0)[0]
    if len(possible_features) == 0:
        return {"size": len(X)}

    feature = int(rng.choice(possible_features))
    min_value = float(X[:, feature].min())
    max_value = float(X[:, feature].max())
    split_value = rng.uniform(min_value, max_value)

    left_mask = X[:, feature] < split_value
    right_mask = ~left_mask

    if not left_mask.any() or not right_mask.any():
        return {"size": len(X)}

    return {
        "feature": feature,
        "split": split_value,
        "left": build_isolation_tree(X[left_mask], depth + 1, max_depth, rng),
        "right": build_isolation_tree(X[right_mask], depth + 1, max_depth, rng),
    }


def path_length(row, tree, depth=0):
    if "size" in tree:
        return depth + c_factor(tree["size"])
    if row[tree["feature"]] < tree["split"]:
        return path_length(row, tree["left"], depth + 1)
    return path_length(row, tree["right"], depth + 1)


def isolation_forest_scores(X, n_trees=100, sample_size=128, random_state=42):
    rng = np.random.default_rng(random_state)
    sample_size = min(sample_size, len(X))
    max_depth = int(math.ceil(math.log2(sample_size))) if sample_size > 1 else 1
    scores = np.zeros(len(X), dtype=float)

    for _ in range(n_trees):
        ids = rng.choice(len(X), size=sample_size, replace=False)
        tree = build_isolation_tree(X[ids], 0, max_depth, rng)
        lengths = np.array([path_length(row, tree) for row in X])
        scores += 2 ** (-lengths / c_factor(sample_size))

    return scores / n_trees


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


def run_models(lst_of_obj, matrix, feature_names, contamination=0.12):
    X_scaled = scale_matrix(matrix)
    isolation_scores = isolation_forest_scores(X_scaled)
    anomaly_border = float(np.quantile(isolation_scores, 1 - contamination))
    is_iforest_anomaly = isolation_scores >= anomaly_border

    results = []
    for i, obj in enumerate(lst_of_obj):
        model_score = float(isolation_scores[i])
        is_malicious = bool(is_iforest_anomaly[i])
        results.append(
            {
                "index": i,
                "ip": obj.ip,
                "requests": obj.amount_of_ip,
                "isolation_score": model_score,
                "final_score": model_score,
                "is_malicious": is_malicious,
                "reason": explain_ip(obj),
            }
        )

    results.sort(key=lambda row: (row["is_malicious"], row["final_score"]), reverse=True)
    return results, isolation_scores, X_scaled


def create_visualizations(results, isolation_scores, output_dir=OUTPUT_DIR):
    output_dir.mkdir(parents=True, exist_ok=True)

    top_results = results[:15]
    plt.figure(figsize=(11, 6))
    plt.bar([row["ip"] for row in top_results], [row["final_score"] for row in top_results], color="#c73e3a")
    plt.title("Top suspicious IPs by Isolation Forest score")
    plt.xlabel("ip")
    plt.ylabel("score")
    plt.xticks(rotation=60, ha="right")
    plt.tight_layout()
    bar_path = output_dir / "top_suspicious_ips.png"
    plt.savefig(bar_path, dpi=160)
    plt.close()

    plt.figure(figsize=(10, 6))
    plt.hist(isolation_scores, bins=25, color="#2f6f9f", alpha=0.85)
    plt.title("Isolation Forest anomaly score distribution")
    plt.xlabel("anomaly score")
    plt.ylabel("ip count")
    plt.tight_layout()
    hist_path = output_dir / "isolation_score_distribution.png"
    plt.savefig(hist_path, dpi=160)
    plt.close()

    return [bar_path, hist_path]


def print_malicious_report(results, image_paths, top_n=20):
    malicious = [row for row in results if row["is_malicious"]]
    print("total_ips:", len(results))
    print("isolation_forest_suspicious_ips:", len(malicious))
    print()
    print("top_suspicious_ips:")
    for row in malicious[:top_n]:
        print(
            f"{row['ip']} | requests={row['requests']} | "
            f"iforest={row['isolation_score']:.4f} | {row['reason']}"
        )
    print()
    print("plots:")
    for path in image_paths:
        print(path)


def save_results_to_csv(results, output_dir=OUTPUT_DIR):
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "malicious_ip_report.csv"
    fields = ["ip", "is_malicious", "requests", "isolation_score", "final_score", "reason"]

    try:
        f = open(csv_path, "w", encoding="utf-8", newline="")
    except PermissionError:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_path = output_dir / f"malicious_ip_report_{stamp}.csv"
        f = open(csv_path, "w", encoding="utf-8", newline="")

    with f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in results:
            writer.writerow({field: row[field] for field in fields})
    return csv_path


def analyze_access_log(PATH, output_dir=OUTPUT_DIR):
    lst_of_obj, matrix, feature_names, ips = prepare_data_for_model(PATH)
    results, isolation_scores, X_scaled = run_models(lst_of_obj, matrix, feature_names)
    image_paths = create_visualizations(results, isolation_scores, output_dir=output_dir)
    csv_path = save_results_to_csv(results, output_dir=output_dir)
    return results, image_paths, csv_path
def count_the_result(results,bad_ips,good_ips):
    false_res=0
    for el in results:
        if el["is_malicious"] or el["is_malicious"] ==  "True":
            if el["ip"] in good_ips: false_res+=1
        else:
            if el["ip"] in bad_ips: false_res+=1
    sum=len(bad_ips)+len(good_ips)
    return round((((sum-false_res)/sum)*100),2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?", default=str(PATH))
    args = parser.parse_args()
    results, image_paths, csv_path = analyze_access_log(Path(args.path))
    print_malicious_report(results, image_paths)
    print()
    print("csv:")
    print(csv_path)
    good_ips=read_the_file(GOOD_IPS).split("\n")
    bad_ips=read_the_file(BAD_IPS).split("\n")
    print(f"The accuracy of the model is: {count_the_result(results,bad_ips,good_ips)} percent")
