//
//  Encryptable.swift
//  ZZWNetworkWrapper
//
//  Created by 张哲炜 on 2022/8/18.
//

import Foundation

public protocol Cryptoable {
    func seal(_ digest: Data) throws -> Data
    func open(_ digest: Data) throws -> Data
}

extension Cryptoable {
    
    func seal(_ digest: Data) throws -> Data {
        return digest
    }
    
    func open(_ digest: Data) throws -> Data {
        return digest
    }
    
}
