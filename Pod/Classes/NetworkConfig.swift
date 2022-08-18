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
    var cryptoService: Cryptoable { get }
}

public struct ApiDataNetworkConfig: NetworkConfigurable {
    
    public let baseURL: URL
    public let headers: [String: String]
    public var cryptoService: Cryptoable
    
     public init(baseURL: URL,
                 headers: [String: String] = [:], cryptoService: Cryptoable) {
        self.baseURL = baseURL
        self.headers = headers
        self.cryptoService = cryptoService
    }
}
