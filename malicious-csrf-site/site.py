from flask import Flask, render_template

app = Flask(__name__
            # , static_folder="./static", template_folder="./malicious-csrf-site/template"
            )


@app.route("/")
def malicious_home():

    return render_template(
        "csrf-demo.html",
        target_url="http://localhost:5000/api/virtual-cards/1/toggle-freeze"
    )

if __name__ == "__main__":
    app.run(host="localhost", port=5001, debug=True)