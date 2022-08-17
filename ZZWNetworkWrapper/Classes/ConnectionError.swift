//
//  ConnectionError.swift
//  ZZWNetworkWrapper
//
//  Created by 张哲炜 on 2022/8/17.
//

import Foundation

public protocol ConnectionError: Error {
    var isInternetConnectionError: Bool { get }
}

public extension Error {
    var isInternetConnectionError: Bool {
        guard let error = self as? ConnectionError, error.isInternetConnectionError else {
            return false
        }
        return true
    }
}
