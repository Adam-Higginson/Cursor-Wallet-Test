// HTTPClient.swift
// Protocol-based HTTP client for testability.
//
// Follows the same pattern as CredentialRepository: a protocol that
// production code implements with URLSession, and tests implement
// with canned responses.

import Foundation

// MARK: - HTTPClient Protocol

/// A minimal HTTP client abstraction for GET and POST requests.
public protocol HTTPClient: Sendable {
    /// Performs an HTTP GET request.
    func get(url: URL) async throws -> (Data, HTTPURLResponse)

    /// Performs an HTTP POST request with optional headers and body.
    func post(url: URL, headers: [String: String], body: Data?) async throws -> (Data, HTTPURLResponse)
}

// MARK: - Errors

/// Errors from the HTTP client layer.
public enum HTTPClientError: Error, Sendable {
    /// The server returned a non-2xx status code.
    case httpError(statusCode: Int, body: Data)
    /// The response was not an HTTP response.
    case invalidResponse
}

// MARK: - URLSessionHTTPClient

/// Production HTTP client backed by URLSession.
public struct URLSessionHTTPClient: HTTPClient {
    private let session: URLSession

    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func get(url: URL) async throws -> (Data, HTTPURLResponse) {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        return try await perform(request)
    }

    public func post(url: URL, headers: [String: String], body: Data?) async throws -> (Data, HTTPURLResponse) {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }
        request.httpBody = body
        return try await perform(request)
    }

    private func perform(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw HTTPClientError.invalidResponse
        }
        guard (200...299).contains(httpResponse.statusCode) else {
            throw HTTPClientError.httpError(statusCode: httpResponse.statusCode, body: data)
        }
        return (data, httpResponse)
    }
}
