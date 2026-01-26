import pickle

with open('classifiers/models/prompt_injection_detector.pkl', 'rb') as f:
    model = pickle.load(f)
    vectorizer = model['vectorizer']
    classifier = model['classifier']


def is_prompt_injection(input_text: str) -> bool:
    """
    Detects if the given input text is a prompt injection attempt.
    """

    X = vectorizer.transform([input_text])
    prediction = classifier.predict(X)
    return prediction[0] == 1

