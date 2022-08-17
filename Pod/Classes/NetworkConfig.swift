//
//  ServiceConfig.swift
//  ExampleMVVM
//
//  Created by Oleh Kudinov on 01.10.18.
//

import Foundation

public protocol NetworkConfigurable {
    var baseURL: URL { get }
    var headers: [String: String] { get }
}

public struct ApiDataNetworkConfig: NetworkConfigurable {
    public let baseURL: URL
    public let headers: [String: String]
    
     public init(baseURL: URL,
                 headers: [String: String] = [:]) {
        self.baseURL = baseURL
        self.headers = headers
    }
}
