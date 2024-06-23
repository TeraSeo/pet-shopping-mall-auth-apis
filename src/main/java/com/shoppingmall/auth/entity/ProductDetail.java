package com.shoppingmall.auth.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "product_detail")
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class ProductDetail extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;
    @Column(nullable = false)
    private String summary;
    @Column(nullable = false)
    private int quantity;
    @Column(nullable = false)
    private int price;
    @Column(nullable = false)
    private int deliveryFee;
    @Column(nullable = false)
    private String image;

    @Column(nullable = false)
    private String subCategory;

    @ManyToOne
    private Product product;

    @ManyToOne
    private User user;

}
