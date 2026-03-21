# Visual Testing with ai-browser-test

devguard dashboard includes visual testing using `ai-browser-test` for AI-powered screenshot validation.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Install Playwright browsers:
```bash
npx playwright install
```

3. Set environment variables:
```bash
export DASHBOARD_URL=http://localhost:8080
export DASHBOARD_API_KEY=your_api_key_here  # Optional, for auth tests
export GEMINI_API_KEY=your_gemini_key  # Or OPENAI_API_KEY
```

## Running Visual Tests

Run all visual tests:
```bash
npm run test:visual
```

Run with UI mode (interactive):
```bash
npm run test:visual:ui
```

## What Gets Tested

1. **Dashboard Homepage**: Validates layout, accessibility, and information display
2. **API Authentication**: Tests API key authentication flow
3. **Error States**: Validates how errors are displayed
4. **Cost Metrics**: Ensures cost information is clearly visible and formatted

## Test Results

Screenshots are saved to `test-results/` directory with timestamps.

Each test returns:
- **Score**: 0-10 rating from AI evaluation
- **Issues**: List of identified problems
- **Cost**: Estimated API cost for the test

## Requirements

- Node.js >= 18.0.0
- Playwright installed
- ai-browser-test package (from sibling directory)
- Dashboard running on configured URL

