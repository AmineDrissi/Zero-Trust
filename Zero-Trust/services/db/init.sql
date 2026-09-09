CREATE TABLE IF NOT EXISTS inference_logs (
    id SERIAL PRIMARY KEY,
    input_text TEXT NOT NULL,
    prediction TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT now()
);

INSERT INTO inference_logs (input_text, prediction) VALUES
    ('is this email spam?', 'spam'),
    ('describe this image', 'a cat sitting on a windowsill'),
    ('summarize this document', 'quarterly revenue increased 12 percent'),
    ('translate hello to french', 'bonjour'),
    ('classify sentiment: great product!', 'positive');
