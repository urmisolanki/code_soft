
"use strict";

// CODSOFT TASK 2: PHISHING AWARENESS QUIZ

const questionBank = [
    {
        id: 1,
        question: "What is phishing?",
        options: [
            { text: "A computer game", correct: false },
            { text: "A trick to steal sensitive information", correct: true },
            { text: "A type of printer", correct: false },
            { text: "A method of backing up files", correct: false }
        ],
        explanation: "Phishing tricks people into revealing private information or taking unsafe actions."
    },
    {
        id: 2,
        question: "What should you do with an unexpected suspicious link?",
        options: [
            { text: "Open it immediately", correct: false },
            { text: "Forward it to everyone", correct: false },
            { text: "Avoid clicking and verify the sender independently", correct: true },
            { text: "Enter your password to check it", correct: false }
        ],
        explanation: "Independent verification helps you avoid fraudulent websites and harmful links."
    },
    {
        id: 3,
        question: "Should you share your OTP with a stranger?",
        options: [
            { text: "Yes, if they ask politely", correct: false },
            { text: "Yes, if they claim to be support staff", correct: false },
            { text: "Only by email", correct: false },
            { text: "No, keep authentication codes private", correct: true }
        ],
        explanation: "Authentication codes can authorize account access or transactions. Never disclose them to strangers."
    },
    {
        id: 4,
        question: "Which is a common warning sign of phishing?",
        options: [
            { text: "An unexpected urgent request for personal details", correct: true },
            { text: "A document you created yourself", correct: false },
            { text: "A bookmarked website you opened directly", correct: false },
            { text: "A normal offline activity", correct: false }
        ],
        explanation: "Unexpected pressure and requests for sensitive information are reasons to stop and verify."
    },
    {
        id: 5,
        question: "Which practice helps protect an online account?",
        options: [
            { text: "Reusing one password everywhere", correct: false },
            { text: "Disabling security notifications", correct: false },
            { text: "Using multi-factor authentication", correct: true },
            { text: "Sharing passwords with friends", correct: false }
        ],
        explanation: "Multi-factor authentication adds another verification step beyond the password."
    },
    {
        id: 6,
        question: "What is spear phishing?",
        options: [
            { text: "A type of computer hardware", correct: false },
            { text: "A targeted phishing attempt against a specific person or group", correct: true },
            { text: "A safe way to share files", correct: false },
            { text: "A network cable standard", correct: false }
        ],
        explanation: "Spear phishing uses tailored messages to make an attack seem more believable."
    },
    {
        id: 7,
        question: "What should you do if an email asks you to reset your password unexpectedly?",
        options: [
            { text: "Click the email link without checking", correct: false },
            { text: "Reply with your current password", correct: false },
            { text: "Ignore all account security forever", correct: false },
            { text: "Visit the official website directly and check your account", correct: true }
        ],
        explanation: "Using the official website independently avoids relying on a potentially fraudulent link."
    },
    {
        id: 8,
        question: "What is SMS phishing commonly called?",
        options: [
            { text: "Smishing", correct: true },
            { text: "Vishing", correct: false },
            { text: "Patching", correct: false },
            { text: "Hashing", correct: false }
        ],
        explanation: "Smishing uses fraudulent text messages to trick people into revealing information or clicking links."
    },
    {
        id: 9,
        question: "How should you check a suspicious email sender?",
        options: [
            { text: "Trust the display name alone", correct: false },
            { text: "Check the full email address and verify through an official channel", correct: true },
            { text: "Assume every email is genuine", correct: false },
            { text: "Reply with your personal details", correct: false }
        ],
        explanation: "Display names can be misleading. Check the full address and verify unexpected requests separately."
    },
    {
        id: 10,
        question: "What is social engineering?",
        options: [
            { text: "Building a computer network", correct: false },
            { text: "Updating an operating system", correct: false },
            { text: "Manipulating people into revealing information or taking unsafe actions", correct: true },
            { text: "Creating a database table", correct: false }
        ],
        explanation: "Social engineering exploits human trust, fear, curiosity, or urgency rather than only technical weaknesses."
    },
    {
        id: 11,
        question: "What should you do after clicking a suspicious link and entering your password?",
        options: [
            { text: "Ignore the incident", correct: false },
            { text: "Change the affected password through the official site, contact the service, and report the incident", correct: true },
            { text: "Send the password to the sender again", correct: false },
            { text: "Reuse the same password everywhere", correct: false }
        ],
        explanation: "Promptly securing the account and reporting the incident can reduce further harm."
    },
    {
        id: 12,
        question: "Why can a fake login page be dangerous?",
        options: [
            { text: "It always improves account security", correct: false },
            { text: "It automatically blocks every attacker", correct: false },
            { text: "It makes your computer faster", correct: false },
            { text: "It can steal credentials entered by the user", correct: true }
        ],
        explanation: "A fraudulent login page may send the entered username and password to an attacker."
    },
    {
        id: 13,
        question: "What is vishing?",
        options: [
            { text: "Voice-call phishing", correct: true },
            { text: "A file compression method", correct: false },
            { text: "A type of firewall", correct: false },
            { text: "A secure backup method", correct: false }
        ],
        explanation: "Vishing uses phone or voice communications to deceive victims."
    },
    {
        id: 14,
        question: "What is the safest way to handle an unexpected attachment?",
        options: [
            { text: "Open it immediately", correct: false },
            { text: "Disable security software before opening it", correct: false },
            { text: "Verify the sender and purpose before opening it", correct: true },
            { text: "Forward it to all your contacts", correct: false }
        ],
        explanation: "Unexpected attachments can contain malicious content. Verify them before opening."
    },
    {
        id: 15,
        question: "What should you do if you suspect a message is phishing?",
        options: [
            { text: "Provide your details to test the sender", correct: false },
            { text: "Report it through the appropriate official channel", correct: true },
            { text: "Click every link in the message", correct: false },
            { text: "Share it publicly without warning anyone", correct: false }
        ],
        explanation: "Reporting suspicious messages can help the relevant organization investigate and protect others."
    }
];

const quizForm = document.getElementById("quizForm");
const questionsContainer = document.getElementById("questionsContainer");
const submitButton = document.getElementById("submitButton");
const tryAgainButton = document.getElementById("tryAgainButton");
const resultBox = document.getElementById("result");
const quizMessage = document.getElementById("quizMessage");
const questionCounter = document.getElementById("questionCounter");
const progressText = document.getElementById("progressText");
const progressBar = document.getElementById("progressBar");

let currentQuestions = [];
let submitted = false;
let lastQuestionSet = [];

// Randomize an array without changing the original.
function shuffleArray(array) {
    const shuffled = [...array];

    for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }

    return shuffled;
}

// Select five random questions.
// Avoid the immediately previous set when possible.
function getRandomQuestions() {
    let shuffledQuestions = shuffleArray(questionBank);
    let selected = shuffledQuestions.slice(0, 5);

    const previousIds = lastQuestionSet.slice().sort((a, b) => a - b);
    const selectedIds = selected.map(q => q.id).sort((a, b) => a - b);

    if (selectedIds.join(",") === previousIds.join(",")) {
        const alternative = shuffledQuestions.slice(5, 10);
        selected = alternative;
    }

    lastQuestionSet = selected.map(q => q.id);

    // Remember the previous set across page refreshes when supported.
    try {
        sessionStorage.setItem(
            "phishingLastQuestionSet",
            JSON.stringify(lastQuestionSet)
        );
    } catch (error) {
        // The quiz still works if session storage is unavailable.
    }

    return selected.map(question => ({
        ...question,
        options: shuffleArray(question.options)
    }));
}

// Restore the previous set so a refresh can avoid repeating it.
try {
    const savedSet = JSON.parse(
        sessionStorage.getItem("phishingLastQuestionSet") || "[]"
    );

    if (Array.isArray(savedSet)) {
        lastQuestionSet = savedSet.filter(
            id => questionBank.some(question => question.id === id)
        );
    }
} catch (error) {
    lastQuestionSet = [];
}

// Show the selected questions and shuffled options.
function renderQuiz() {
    questionsContainer.replaceChildren();
    quizMessage.textContent = "";
    resultBox.replaceChildren();
    resultBox.hidden = true;

    currentQuestions.forEach((question, index) => {
        const card = document.createElement("div");
        card.className = "question";
        card.dataset.questionId = question.id;

        const heading = document.createElement("h3");
        heading.textContent = `${index + 1}. ${question.question}`;
        card.appendChild(heading);

        question.options.forEach((option, optionIndex) => {
            const label = document.createElement("label");
            const radio = document.createElement("input");

            radio.type = "radio";
            radio.name = `question-${question.id}`;
            radio.value = String(optionIndex);
            radio.required = true;

            label.appendChild(radio);
            label.appendChild(document.createTextNode(option.text));

            card.appendChild(label);
        });

        const feedback = document.createElement("div");
        feedback.className = "feedback";
        feedback.hidden = true;
        feedback.setAttribute("aria-live", "polite");

        card.appendChild(feedback);
        questionsContainer.appendChild(card);
    });

    submitted = false;
    submitButton.disabled = false;
    submitButton.hidden = false;
    tryAgainButton.hidden = true;

    questionCounter.textContent = "5 questions selected";
    progressText.textContent = "Question 1 of 5";
    progressBar.style.width = "20%";
}

// Update progress when an answer is selected.
questionsContainer.addEventListener("change", event => {
    if (submitted || event.target.type !== "radio") {
        return;
    }

    const answeredCount = currentQuestions.filter(question =>
        quizForm.querySelector(
            `input[name="question-${question.id}"]:checked`
        )
    ).length;

    progressText.textContent = `${answeredCount} of 5 answered`;
    progressBar.style.width = `${answeredCount * 20}%`;
});

// Create safe feedback using textContent.
function addFeedbackLine(container, label, value) {
    const paragraph = document.createElement("p");
    const strong = document.createElement("strong");

    strong.textContent = label + ": ";
    paragraph.appendChild(strong);
    paragraph.appendChild(document.createTextNode(value));
    container.appendChild(paragraph);
}

// Calculate score and display detailed results.
quizForm.addEventListener("submit", event => {
    event.preventDefault();

    if (submitted) {
        return;
    }

    const unanswered = currentQuestions.filter(question =>
        !quizForm.querySelector(
            `input[name="question-${question.id}"]:checked`
        )
    );

    if (unanswered.length > 0) {
        quizMessage.textContent =
            `Please answer all questions. ${unanswered.length} remaining.`;
        return;
    }

    submitted = true;
    submitButton.disabled = true;
    submitButton.hidden = true;
    tryAgainButton.hidden = false;
    quizMessage.textContent = "";

    let score = 0;

    currentQuestions.forEach((question, index) => {
        const card = questionsContainer.children[index];
        const selectedRadio = card.querySelector("input:checked");
        const selectedOption = question.options[
            Number(selectedRadio.value)
        ];
        const correctOption = question.options.find(option => option.correct);
        const isCorrect = selectedOption.correct;

        if (isCorrect) {
            score++;
        }

        // Disable answers after submission.
        card.querySelectorAll("input").forEach(input => {
            input.disabled = true;
        });

        // Mark the correct answer and the selected incorrect answer.
        card.querySelectorAll("label").forEach((label, optionIndex) => {
            const option = question.options[optionIndex];

            if (option.correct) {
                label.classList.add("correct-option");
            }

            if (optionIndex === Number(selectedRadio.value) && !isCorrect) {
                label.classList.add("incorrect-option");
            }
        });

        const feedback = card.querySelector(".feedback");
        feedback.hidden = false;
        feedback.classList.add(isCorrect ? "correct" : "incorrect");

        const status = document.createElement("h4");
        status.textContent = isCorrect
            ? "Correct answer!"
            : "Incorrect answer";
        feedback.appendChild(status);

        addFeedbackLine(feedback, "Your answer", selectedOption.text);

        if (!isCorrect) {
            addFeedbackLine(
                feedback,
                "Correct answer",
                correctOption.text
            );
        }

        addFeedbackLine(feedback, "Explanation", question.explanation);
    });

    const percentage = Math.round((score / currentQuestions.length) * 100);

    const summary = document.createElement("div");
    summary.className = "result-card";

    const title = document.createElement("h3");
    title.textContent = "Quiz Results";
    summary.appendChild(title);

    const scoreText = document.createElement("p");
    scoreText.className = "result-score";
    scoreText.textContent = `${score}/5`;
    summary.appendChild(scoreText);

    const percentageText = document.createElement("p");
    percentageText.textContent = `Percentage: ${percentage}%`;
    summary.appendChild(percentageText);

    const message = document.createElement("p");

    if (score === 5) {
        message.textContent = "Excellent! You answered every question correctly.";
    } else if (score >= 3) {
        message.textContent = "Good effort! Review the explanations to improve.";
    } else {
        message.textContent = "Keep learning! Review the safety tips and try again.";
    }

    summary.appendChild(message);
    resultBox.appendChild(summary);
    resultBox.hidden = false;

    questionCounter.textContent = "Quiz completed";
    progressText.textContent = "5 of 5 answered";
    progressBar.style.width = "100%";

    resultBox.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
});

// Load a fresh quiz without reloading the page.
tryAgainButton.addEventListener("click", () => {
    currentQuestions = getRandomQuestions();
    renderQuiz();

    document.getElementById("quiz").scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
});

// Start a random quiz on page load.
currentQuestions = getRandomQuestions();
renderQuiz();
