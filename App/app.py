from flask import Flask, render_template, request
from phishingdetection import predict

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def main():
    if request.method == "POST":
        url = request.form.get("url")
        prediction = predict(url)

        if prediction == 1:
            prediction = "SAFE"
        else:
            prediction = "PHISHING"

        return render_template("result.html", prediction=prediction)
    else:
        return render_template("homepage.html")


if __name__ == "__main__":
    app.run(debug=True)
