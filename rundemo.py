from datetime import datetime
import json

from ml_inference import BASE_DIR, DATASETS_DIR, EIRPInferenceEngine, build_report, print_console_report


def run_demo(engine: EIRPInferenceEngine) -> None:
  
    demo_sources = [
        ("lira",   DATASETS_DIR / "model_01_db_downtime_classifier" / "X_test.pkl",
                   DATASETS_DIR / "model_01_db_downtime_classifier" / "label_encoder.pkl",
                   DATASETS_DIR / "model_01_db_downtime_classifier" / "metadata.json"),
        ("access", DATASETS_DIR / "model_04_web_traffic_anomaly_classifier" / "X_test.pkl",
                   DATASETS_DIR / "model_04_web_traffic_anomaly_classifier" / "label_encoder.pkl",
                   DATASETS_DIR / "model_04_web_traffic_anomaly_classifier" / "metadata.json"),
    ]

    for source, X_path, le_path, meta_path in demo_sources:
        if X_path.exists() and meta_path.exists():
            X_test  = joblib.load(X_path)
            meta    = json.loads(meta_path.read_text())
            feat_names = meta.get("feature_names", [f"f{i}" for i in range(X_test.shape[1])])

            # Reconstruct a DataFrame from the saved numpy array
            df_demo = pd.DataFrame(X_test, columns=feat_names)
            
            if source == "lira" and "severity_score" not in df_demo.columns:
                df_demo["severity_score"] = df_demo.get("severity_score",
                    pd.Series(np.random.uniform(0,10,len(df_demo))))

            print(f"  [DEMO] Source: {source.upper()} | {len(df_demo):,} test events")
            df_scored = engine.score(df_demo, source)
            report    = build_report(df_scored, source, "DEMO_ML_Datasets", engine)
            print_console_report(report, df_scored)

            out = BASE_DIR / f"eirp_demo_report_{datetime.now():%Y%m%d_%H%M%S}.json"
            out.write_text(json.dumps(report, indent=2, default=str))
            print(f"  [SAVED] Demo report -> {out.name}")
            return

    print("  [WARN] No ML_Datasets found. Run ml_dataset_builder.py first.")

