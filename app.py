from flask import Flask, render_template, request
from detector import detect_phishing
from ml_detector import predict_url

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    score = 0
    risk_level = None

    ml_result = None
    ml_confidence = None

    reasons = []
    url = ""

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if url:

            result, score, risk_level, reasons = detect_phishing(url)

            ml_result, ml_confidence = predict_url(url)

    return render_template(
        "index.html",
        result=result,
        score=score,
        risk_level=risk_level,
        ml_result=ml_result,
        ml_confidence=ml_confidence,
        reasons=reasons,
        url=url
    )


if __name__ == "__main__":
    app.run(debug=True)